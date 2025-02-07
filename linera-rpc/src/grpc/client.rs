// Copyright (c) Zefchain Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    fmt,
    future::Future,
    iter,
    sync::{Arc, Mutex},
};

use futures::{future, stream, StreamExt};
use lazy_static::lazy_static;
use linera_base::{
    crypto::CryptoHash,
    data_types::{Blob, BlobContent},
    identifiers::{BlobId, ChainId},
    time::{Duration, Instant},
};
use linera_chain::data_types::{self, Certificate, CertificateValue, HashedCertificateValue};
use linera_core::{
    node::{CrossChainMessageDelivery, NodeError, NotificationStream, ValidatorNode},
    worker::Notification,
};
use linera_version::VersionInfo;
use tonic::{Code, IntoRequest, Request, Status};
use tracing::{debug, error, info, instrument};
#[cfg(not(web))]
use {
    super::GrpcProtoConversionError,
    crate::{mass_client, RpcMessage},
};

use super::{
    api::{
        self, chain_info_result::Inner, validator_node_client::ValidatorNodeClient,
        SubscriptionRequest,
    },
    transport, GrpcError, GRPC_MAX_MESSAGE_SIZE,
};
use crate::{
    config::ValidatorPublicNetworkConfig, node_provider::NodeOptions, HandleCertificateRequest,
    HandleLiteCertRequest,
};

#[derive(Clone)]
struct ClientMetrics {
    requests: u128,
    request_errors: u128,
    total_request_delay_ms: u128,
    total_error_delay_ms: u128,
    last_window_delay_ms: u128,

    subscribed_chains: HashMap<ChainId, Instant>,
    subscribed_at: Instant,
    subscription_total_reconects: usize,
    subscription_window_subscribe_at: Instant,
    subscription_window_reconnects: usize,
}

lazy_static! {
    static ref CLIENT_METRICS: Arc<Mutex<HashMap<String, ClientMetrics>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

#[derive(Clone)]
pub struct GrpcClient {
    address: String,
    client: ValidatorNodeClient<transport::Channel>,
    retry_delay: Duration,
    max_retries: u32,
}

fn client_request(address: String) {
    match CLIENT_METRICS.lock() {
        Ok(mut guard) => match guard.get(&address) {
            Some(metrics) => {
                let mut metrics = metrics.clone();
                metrics.requests += 1;
                guard.insert(address, metrics);
            }
            _ => {}
        },
        _ => {}
    }
}

fn client_response(address: String, success: bool, elapsed: u128) {
    match CLIENT_METRICS.lock() {
        Ok(mut guard) => match guard.get(&address) {
            Some(metrics) => {
                let mut metrics = metrics.clone();
                if !success {
                    metrics.request_errors += 1;
                    metrics.total_error_delay_ms += elapsed;
                }
                metrics.total_request_delay_ms += elapsed;
                metrics.last_window_delay_ms += elapsed;
                guard.insert(address, metrics);
            }
            _ => {}
        },
        _ => {}
    }
}

fn client_subscribe_chain(address: String, chain_id: ChainId) {
    match CLIENT_METRICS.lock() {
        Ok(mut guard) => match guard.get(&address) {
            Some(metrics) => {
                let mut metrics = metrics.clone();
                metrics.subscribed_chains.insert(chain_id, Instant::now());
                guard.insert(address, metrics);
            }
            _ => {}
        },
        _ => {}
    }
}

fn client_retry_subscribe_chain(address: String) {
    match CLIENT_METRICS.lock() {
        Ok(mut guard) => match guard.get(&address) {
            Some(metrics) => {
                let mut metrics = metrics.clone();
                metrics.subscription_total_reconects += 1;
                metrics.subscription_window_reconnects += 1;
                if metrics
                    .subscription_window_subscribe_at
                    .elapsed()
                    .as_millis()
                    > 300000
                {
                    metrics.subscription_window_subscribe_at = Instant::now();
                    metrics.subscription_window_reconnects = 0;
                }
                guard.insert(address, metrics);
            }
            _ => {}
        },
        _ => {}
    }
}

fn client_print_if_needed(address: String) {
    match CLIENT_METRICS.lock() {
        Ok(mut guard) => match guard.get(&address) {
            Some(metrics) => {
                if metrics.last_window_delay_ms >= 60000 && metrics.requests > 0 {
                    info!(
                        "{} requests {} errors {} average rtt {}ms average success rtt {}ms average error rtt {}ms chains {} reconnects {}/{} elapsed {}ms/{}ms",
                        address,
                        metrics.requests,
                        metrics.request_errors,
                        metrics.total_request_delay_ms / metrics.requests,
                        if metrics.requests > metrics.request_errors {
                            (metrics.total_request_delay_ms - metrics.total_error_delay_ms) / (metrics.requests - metrics.request_errors)
                        } else {
                            0
                        },
                        if metrics.request_errors > 0 {
                            metrics.total_error_delay_ms / metrics.request_errors
                        } else {
                            0
                        },
                        metrics.subscribed_chains.len(),
                        metrics.subscription_window_reconnects,
                        metrics.subscription_total_reconects,
                        metrics.subscription_window_subscribe_at.elapsed().as_millis(),
                        metrics.subscribed_at.elapsed().as_millis(),
                    );
                    let mut metrics = metrics.clone();
                    metrics.last_window_delay_ms = 0;
                    guard.insert(address, metrics);
                }
            }
            _ => {}
        },
        _ => {}
    }
}

impl GrpcClient {
    pub fn new(
        network: ValidatorPublicNetworkConfig,
        options: NodeOptions,
    ) -> Result<Self, GrpcError> {
        let address = network.http_address();

        let channel =
            transport::create_channel(address.clone(), &transport::Options::from(&options))?;
        let client = ValidatorNodeClient::new(channel)
            .max_encoding_message_size(GRPC_MAX_MESSAGE_SIZE)
            .max_decoding_message_size(GRPC_MAX_MESSAGE_SIZE);

        let mut metrics = CLIENT_METRICS.lock().unwrap();
        let client_metrics = ClientMetrics {
            requests: 0,
            request_errors: 0,
            total_request_delay_ms: 0,
            total_error_delay_ms: 0,
            last_window_delay_ms: 0,

            subscribed_chains: HashMap::new(),
            subscribed_at: Instant::now(),
            subscription_total_reconects: 0,
            subscription_window_subscribe_at: Instant::now(),
            subscription_window_reconnects: 0,
        };
        metrics.entry(address.clone()).or_insert(client_metrics);

        Ok(Self {
            address,
            client,
            retry_delay: options.retry_delay,
            max_retries: options.max_retries,
        })
    }

    /// Returns whether this gRPC status means the server stream should be reconnected to, or not.
    /// Logs a warning on unexpected status codes.
    fn is_retryable(status: &Status) -> bool {
        match status.code() {
            Code::DeadlineExceeded | Code::Aborted | Code::Unavailable | Code::Unknown => {
                debug!("gRPC request interrupted: {}; retrying", status);
                true
            }
            Code::Ok | Code::Cancelled | Code::ResourceExhausted => {
                error!("Unexpected gRPC status: {}; retrying", status);
                true
            }
            Code::InvalidArgument
            | Code::NotFound
            | Code::AlreadyExists
            | Code::PermissionDenied
            | Code::FailedPrecondition
            | Code::OutOfRange
            | Code::Unimplemented
            | Code::DataLoss
            | Code::Unauthenticated => {
                debug!("Unexpected gRPC status: {}", status);
                false
            }
        }
    }

    async fn delegate<F, Fut, R, S>(
        &self,
        f: F,
        request: impl TryInto<R> + fmt::Debug + Clone,
        handler: &str,
    ) -> Result<S, NodeError>
    where
        F: Fn(ValidatorNodeClient<transport::Channel>, Request<R>) -> Fut,
        Fut: Future<Output = Result<tonic::Response<S>, Status>>,
        R: IntoRequest<R> + Clone,
    {
        debug!(request = ?request, "sending gRPC request");
        let mut retry_count = 0;
        let request_inner = request.try_into().map_err(|_| NodeError::GrpcError {
            error: "could not convert request to proto".to_string(),
        })?;
        let address = self.address.clone();
        loop {
            client_print_if_needed(address.clone());
            client_request(address.clone());
            let request_at = Instant::now();

            match f(self.client.clone(), Request::new(request_inner.clone())).await {
                Err(s) if Self::is_retryable(&s) && retry_count < self.max_retries => {
                    let elapsed = request_at.elapsed().as_millis();
                    client_response(address.clone(), false, elapsed);

                    let delay = self.retry_delay.saturating_mul(retry_count);
                    retry_count += 1;
                    linera_base::time::timer::sleep(delay).await;
                    continue;
                }
                Err(s) => {
                    let elapsed = request_at.elapsed().as_millis();
                    client_response(address.clone(), false, elapsed);

                    return Err(NodeError::GrpcError {
                        error: format!("remote request [{handler}] failed with status: {s:?}",),
                    });
                }
                Ok(result) => {
                    let elapsed = request_at.elapsed().as_millis();
                    client_response(address.clone(), true, elapsed);
                    return Ok(result.into_inner());
                }
            };
        }
    }

    #[allow(clippy::result_large_err)]
    fn try_into_chain_info(
        result: api::ChainInfoResult,
    ) -> Result<linera_core::data_types::ChainInfoResponse, NodeError> {
        let inner = result.inner.ok_or(NodeError::GrpcError {
            error: "missing body from response".to_string(),
        })?;
        match inner {
            Inner::ChainInfoResponse(response) => {
                Ok(response.try_into().map_err(|err| NodeError::GrpcError {
                    error: format!("failed to unmarshal response: {}", err),
                })?)
            }
            Inner::Error(error) => {
                Err(
                    bincode::deserialize(&error).map_err(|err| NodeError::GrpcError {
                        error: format!("failed to unmarshal error message: {}", err),
                    })?,
                )
            }
        }
    }
}

macro_rules! client_delegate {
    ($self:ident, $handler:ident, $req:ident) => {{
        $self
            .delegate(
                |mut client, req| async move { client.$handler(req).await },
                $req,
                stringify!($handler),
            )
            .await
    }};
}

impl ValidatorNode for GrpcClient {
    type NotificationStream = NotificationStream;

    #[instrument(target = "grpc_client", skip_all, err, fields(address = self.address))]
    async fn handle_block_proposal(
        &self,
        proposal: data_types::BlockProposal,
    ) -> Result<linera_core::data_types::ChainInfoResponse, NodeError> {
        GrpcClient::try_into_chain_info(client_delegate!(self, handle_block_proposal, proposal)?)
    }

    #[instrument(target = "grpc_client", skip_all, fields(address = self.address))]
    async fn handle_lite_certificate(
        &self,
        certificate: data_types::LiteCertificate<'_>,
        delivery: CrossChainMessageDelivery,
    ) -> Result<linera_core::data_types::ChainInfoResponse, NodeError> {
        let wait_for_outgoing_messages = delivery.wait_for_outgoing_messages();
        let request = HandleLiteCertRequest {
            certificate,
            wait_for_outgoing_messages,
        };
        GrpcClient::try_into_chain_info(client_delegate!(self, handle_lite_certificate, request)?)
    }

    #[instrument(target = "grpc_client", skip_all, err, fields(address = self.address))]
    async fn handle_certificate(
        &self,
        certificate: Certificate,
        blobs: Vec<Blob>,
        delivery: CrossChainMessageDelivery,
    ) -> Result<linera_core::data_types::ChainInfoResponse, NodeError> {
        let wait_for_outgoing_messages = delivery.wait_for_outgoing_messages();
        let request = HandleCertificateRequest {
            certificate,
            blobs,
            wait_for_outgoing_messages,
        };
        GrpcClient::try_into_chain_info(client_delegate!(self, handle_certificate, request)?)
    }

    #[instrument(target = "grpc_client", skip_all, err, fields(address = self.address))]
    async fn handle_chain_info_query(
        &self,
        query: linera_core::data_types::ChainInfoQuery,
    ) -> Result<linera_core::data_types::ChainInfoResponse, NodeError> {
        GrpcClient::try_into_chain_info(client_delegate!(self, handle_chain_info_query, query)?)
    }

    #[instrument(target = "grpc_client", skip_all, err, fields(address = self.address))]
    async fn subscribe(&self, chains: Vec<ChainId>) -> Result<Self::NotificationStream, NodeError> {
        let address = self.address.clone();
        let subscribe_address = self.address.clone();
        let retry_delay = self.retry_delay;
        let max_retries = self.max_retries;
        let mut retry_count = 0;
        let subscription_request = SubscriptionRequest {
            chain_ids: chains
                .clone()
                .into_iter()
                .map(|chain| chain.into())
                .collect(),
        };
        let mut client = self.client.clone();

        // Make the first connection attempt before returning from this method.
        let mut stream = Some(
            client
                .subscribe(subscription_request.clone())
                .await
                .map_err(|status| NodeError::SubscriptionFailed {
                    status: status.to_string(),
                })?
                .into_inner(),
        );

        for chain_id in chains {
            client_subscribe_chain(address.clone(), chain_id);
        }

        // A stream of `Result<grpc::Notification, tonic::Status>` that keeps calling
        // `client.subscribe(request)` endlessly and without delay.
        let endlessly_retrying_notification_stream = stream::unfold((), move |()| {
            let mut client = client.clone();
            let subscription_request = subscription_request.clone();
            let mut stream = stream.take();
            let address = subscribe_address.clone();
            async move {
                let stream = if let Some(stream) = stream.take() {
                    future::Either::Right(stream)
                } else {
                    client_retry_subscribe_chain(address.clone());

                    match client.subscribe(subscription_request.clone()).await {
                        Err(err) => future::Either::Left(stream::iter(iter::once(Err(err)))),
                        Ok(response) => future::Either::Right(response.into_inner()),
                    }
                };
                Some((stream, ()))
            }
        })
        .flatten();

        // The stream of `Notification`s that inserts increasing delays after retriable errors, and
        // terminates after unexpected or fatal errors.
        let notification_stream = endlessly_retrying_notification_stream
            .map(|result| {
                Option::<Notification>::try_from(result?).map_err(|err| {
                    let message = format!("Could not deserialize notification: {}", err);
                    tonic::Status::new(Code::Internal, message)
                })
            })
            .take_while(move |result| {
                let Err(status) = result else {
                    retry_count = 0;
                    return future::Either::Left(future::ready(true));
                };
                if !Self::is_retryable(status) || retry_count >= max_retries {
                    error!(
                        "{} notification Error {}, {:?} {} retries",
                        address,
                        status.code(),
                        status,
                        retry_count
                    );
                    return future::Either::Left(future::ready(false));
                }
                let delay = retry_delay.saturating_mul(retry_count);
                retry_count += 1;
                future::Either::Right(async move {
                    linera_base::time::timer::sleep(delay).await;
                    true
                })
            })
            .filter_map(|result| {
                future::ready(match result {
                    Ok(notification @ Some(_)) => notification,
                    Ok(None) => None,
                    Err(err) => {
                        debug!("{}", err);
                        None
                    }
                })
            });

        Ok(Box::pin(notification_stream))
    }

    #[instrument(target = "grpc_client", skip_all, err, fields(address = self.address))]
    async fn get_version_info(&self) -> Result<VersionInfo, NodeError> {
        let req = ();
        Ok(client_delegate!(self, get_version_info, req)?.into())
    }

    #[instrument(target = "grpc_client", skip_all, err, fields(address = self.address))]
    async fn get_genesis_config_hash(&self) -> Result<CryptoHash, NodeError> {
        let req = ();
        Ok(client_delegate!(self, get_genesis_config_hash, req)?.try_into()?)
    }

    #[instrument(target = "grpc_client", skip(self), err, fields(address = self.address))]
    async fn download_blob_content(&self, blob_id: BlobId) -> Result<BlobContent, NodeError> {
        let req = api::BlobId::try_from(blob_id)?;
        Ok(client_delegate!(self, download_blob_content, req)?.try_into()?)
    }

    #[instrument(target = "grpc_client", skip_all, err, fields(address = self.address))]
    async fn download_certificate_value(
        &self,
        hash: CryptoHash,
    ) -> Result<HashedCertificateValue, NodeError> {
        let value = client_delegate!(self, download_certificate_value, hash)?;
        Ok(CertificateValue::try_from(value)?.with_hash_checked(hash)?)
    }

    #[instrument(target = "grpc_client", skip_all, err, fields(address = self.address))]
    async fn download_certificate(&self, hash: CryptoHash) -> Result<Certificate, NodeError> {
        Ok(client_delegate!(self, download_certificate, hash)?.try_into()?)
    }

    #[instrument(target = "grpc_client", skip_all, err, fields(address = self.address))]
    async fn download_certificates(
        &self,
        hashes: Vec<CryptoHash>,
    ) -> Result<Vec<Certificate>, NodeError> {
        let mut missing_hashes = hashes;
        let mut certs_collected = Vec::with_capacity(missing_hashes.len());
        loop {
            // Macro doesn't compile if we pass `missing_hashes.clone()` directly to `client_delegate!`.
            let missing = missing_hashes.clone();
            let mut received: Vec<Certificate> =
                client_delegate!(self, download_certificates, missing)?.try_into()?;

            // In the case of the server not returning any certificates, we break the loop.
            if received.is_empty() {
                break;
            }

            // Honest validator should return certificates in the same order as the requested hashes.
            missing_hashes = missing_hashes[received.len()..].to_vec();
            certs_collected.append(&mut received);
        }
        Ok(certs_collected)
    }

    #[instrument(target = "grpc_client", skip(self), err, fields(address = self.address))]
    async fn blob_last_used_by(&self, blob_id: BlobId) -> Result<CryptoHash, NodeError> {
        let req = api::BlobId::try_from(blob_id)?;
        Ok(client_delegate!(self, blob_last_used_by, req)?.try_into()?)
    }
}

#[cfg(not(web))]
#[async_trait::async_trait]
impl mass_client::MassClient for GrpcClient {
    #[instrument(skip_all, err)]
    async fn send(
        &self,
        requests: Vec<RpcMessage>,
        max_in_flight: usize,
    ) -> Result<Vec<RpcMessage>, mass_client::MassClientError> {
        let client = self.client.clone();
        let responses = stream::iter(requests)
            .map(|request| {
                let mut client = client.clone();
                async move {
                    let response = match request {
                        RpcMessage::BlockProposal(proposal) => {
                            let request = Request::new((*proposal).try_into()?);
                            client.handle_block_proposal(request).await?
                        }
                        RpcMessage::Certificate(request) => {
                            let request = Request::new((*request).try_into()?);
                            client.handle_certificate(request).await?
                        }
                        msg => panic!("attempted to send msg: {:?}", msg),
                    };
                    match response
                        .into_inner()
                        .inner
                        .ok_or(GrpcProtoConversionError::MissingField)?
                    {
                        Inner::ChainInfoResponse(chain_info_response) => {
                            Ok(Some(RpcMessage::ChainInfoResponse(Box::new(
                                chain_info_response.try_into()?,
                            ))))
                        }
                        Inner::Error(error) => {
                            let error = bincode::deserialize::<NodeError>(&error)
                                .map_err(GrpcProtoConversionError::BincodeError)?;
                            tracing::error!(?error, "received error response");
                            Ok(None)
                        }
                    }
                }
            })
            .buffer_unordered(max_in_flight)
            .filter_map(
                |result: Result<Option<_>, mass_client::MassClientError>| async move {
                    result.transpose()
                },
            )
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        Ok(responses)
    }
}
