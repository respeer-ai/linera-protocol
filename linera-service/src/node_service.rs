// Copyright (c) Zefchain Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Context};
use async_graphql::{
    futures_util::Stream,
    parser::types::{DocumentOperations, ExecutableDocument, OperationType},
    Error, MergedObject, Object, Request, ScalarType, Schema, ServerError, SimpleObject,
    Subscription,
};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse, GraphQLSubscription};
use axum::{extract::Path, http::StatusCode, response, response::IntoResponse, Extension, Router};
use futures::{
    future::{self},
    lock::{Mutex, MutexGuard, OwnedMutexGuard},
    Future,
};
use linera_base::{
    crypto::{CryptoError, CryptoHash, Hashable, PublicKey, Signature},
    data_types::{Amount, ApplicationPermissions, Blob, BlockHeight, TimeDelta, Timestamp},
    identifiers::{Account, ApplicationId, BlobId, BytecodeId, ChainId, MessageId, Owner},
    ownership::{ChainOwnership, TimeoutConfig},
    BcsHexParseError,
};
use linera_chain::{
    data_types::{CertificateValue, HashedCertificateValue, IncomingMessage, ProposalPayload},
    ChainStateView,
};
use linera_core::{
    client::{ArcChainClient, ChainClient, ChainClientError},
    data_types::{ClientOutcome, RoundTimeout},
    local_node::LocalNodeClient,
    node::{LocalValidatorNodeProvider, NotificationStream, ValidatorNode, ValidatorNodeProvider},
    notifier::Notifier,
    worker::{Notification, Reason, WorkerState},
};
use linera_execution::{
    committee::{Committee, Epoch},
    system::{AdminOperation, Recipient, SystemChannel, UserData},
    Bytecode, Message, Operation, Query, Response, SystemMessage, SystemOperation,
    UserApplicationDescription, UserApplicationId,
};
use linera_storage::Storage;
use linera_views::views::ViewError;
use local_ip_address::local_ip;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    borrow::Cow,
    collections::BTreeMap,
    collections::HashMap,
    iter,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU16,
    sync::Arc,
};
use thiserror::Error as ThisError;
use tokio_stream::StreamExt;
use tower_http::cors::CorsLayer;
use tracing::{debug, error, info};

use crate::{
    chain_listener::{ChainListener, ChainListenerConfig, ClientContext},
    cli_wrappers, util,
};

#[derive(SimpleObject, Serialize, Deserialize, Clone)]
pub struct Chains {
    pub list: Vec<ChainId>,
    pub default: Option<ChainId>,
}

pub type ClientMapInner<P, S> = BTreeMap<ChainId, ArcChainClient<P, S>>;
pub(crate) struct ChainClients<P, S>(Arc<Mutex<ClientMapInner<P, S>>>);

impl<P, S> Clone for ChainClients<P, S> {
    fn clone(&self) -> Self {
        ChainClients(self.0.clone())
    }
}

impl<P, S> Default for ChainClients<P, S> {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(BTreeMap::new())))
    }
}

impl<P, S> ChainClients<P, S> {
    async fn client(&self, chain_id: &ChainId) -> Option<ArcChainClient<P, S>> {
        Some(self.0.lock().await.get(chain_id)?.clone())
    }

    pub(crate) async fn client_lock(
        &self,
        chain_id: &ChainId,
    ) -> Option<OwnedMutexGuard<ChainClient<P, S>>> {
        Some(self.client(chain_id).await?.0.lock_owned().await)
    }

    pub(crate) async fn try_client_lock(
        &self,
        chain_id: &ChainId,
    ) -> Result<OwnedMutexGuard<ChainClient<P, S>>, Error> {
        self.client_lock(chain_id)
            .await
            .ok_or_else(|| Error::new(format!("Unknown chain ID: {}", chain_id)))
    }

    pub(crate) async fn map_lock(&self) -> MutexGuard<ClientMapInner<P, S>> {
        self.0.lock().await
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, SimpleObject)]
pub struct RawBlockProposalPayload {
    pub height: BlockHeight,
    pub payload_bytes: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SimpleObject)]
pub struct ChainAccountBalances {
    chain_balance: Amount,
    account_balances: HashMap<PublicKey, Amount>,
}

/// Our root GraphQL query type.
pub struct QueryRoot<P, S> {
    clients: ChainClients<P, S>,
    port: NonZeroU16,
    default_chain: Option<ChainId>,
}

/// Our root GraphQL subscription type.
pub struct SubscriptionRoot<P, S> {
    clients: ChainClients<P, S>,
}

/// Our root GraphQL mutation type.
pub struct MutationRoot<P, S, C> {
    storage: S,
    clients: ChainClients<P, S>,
    context: Arc<Mutex<C>>,
    config: ChainListenerConfig,
}

#[derive(Debug, ThisError)]
enum NodeServiceError {
    #[error(transparent)]
    ChainClientError(#[from] ChainClientError),
    #[error(transparent)]
    BcsHexError(#[from] BcsHexParseError),
    #[error("could not decode query string")]
    QueryStringError(#[from] hex::FromHexError),
    #[error(transparent)]
    BcsError(#[from] bcs::Error),
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    #[error("missing GraphQL operation")]
    MissingOperation,
    #[error("unsupported query type: subscription")]
    UnsupportedQueryType,
    #[error("GraphQL operations of different types submitted")]
    HeterogeneousOperations,
    #[error("failed to parse GraphQL query: {error}")]
    GraphQLParseError { error: String },
    #[error("malformed application response")]
    MalformedApplicationResponse,
    #[error("application service error")]
    ApplicationServiceError { errors: Vec<String> },
    #[error("chain ID not found")]
    UnknownChainId { chain_id: String },
    #[error("malformed chain ID")]
    InvalidChainId(CryptoError),

    #[error("Unexpected certificate. Please make sure you are connecting to the right network and are using a current software version.")]
    UnexpectedCertificate,
    #[error("The message with the ID returned by the faucet is not OpenChain. please make sure you are connecting to a genuine faucet.")]
    NotOpenChainMessage,
}

impl From<ServerError> for NodeServiceError {
    fn from(value: ServerError) -> Self {
        NodeServiceError::GraphQLParseError {
            error: value.to_string(),
        }
    }
}

impl IntoResponse for NodeServiceError {
    fn into_response(self) -> response::Response {
        let tuple = match self {
            NodeServiceError::BcsHexError(e) => (StatusCode::BAD_REQUEST, vec![e.to_string()]),
            NodeServiceError::QueryStringError(e) => (StatusCode::BAD_REQUEST, vec![e.to_string()]),
            NodeServiceError::ChainClientError(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, vec![e.to_string()])
            }
            NodeServiceError::BcsError(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, vec![e.to_string()])
            }
            NodeServiceError::JsonError(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, vec![e.to_string()])
            }
            NodeServiceError::MalformedApplicationResponse => {
                (StatusCode::INTERNAL_SERVER_ERROR, vec![self.to_string()])
            }
            NodeServiceError::MissingOperation
            | NodeServiceError::HeterogeneousOperations
            | NodeServiceError::UnsupportedQueryType => {
                (StatusCode::BAD_REQUEST, vec![self.to_string()])
            }
            NodeServiceError::GraphQLParseError { error } => (StatusCode::BAD_REQUEST, vec![error]),
            NodeServiceError::ApplicationServiceError { errors } => {
                (StatusCode::BAD_REQUEST, errors)
            }
            NodeServiceError::UnknownChainId { chain_id } => (
                StatusCode::NOT_FOUND,
                vec![format!("unknown chain ID: {}", chain_id)],
            ),
            NodeServiceError::InvalidChainId(_) => (
                StatusCode::BAD_REQUEST,
                vec!["invalid chain ID".to_string()],
            ),
            NodeServiceError::UnexpectedCertificate => {
                (StatusCode::BAD_REQUEST, vec![self.to_string()])
            }
            NodeServiceError::NotOpenChainMessage => {
                (StatusCode::BAD_REQUEST, vec![self.to_string()])
            }
        };
        let tuple = (tuple.0, json!({"error": tuple.1}).to_string());
        tuple.into_response()
    }
}

#[Subscription]
impl<P, S> SubscriptionRoot<P, S>
where
    P: ValidatorNodeProvider + Send + Sync + 'static,
    S: Storage + Clone + Send + Sync + 'static,
    ViewError: From<S::ContextError>,
{
    /// Subscribes to notifications from the specified chain.
    async fn notifications(
        &self,
        chain_id: ChainId,
    ) -> Result<impl Stream<Item = Notification>, Error> {
        let mut client = self.clients.try_client_lock(&chain_id).await?;
        Ok(client.subscribe().await?)
    }
}

impl<P, S, C> MutationRoot<P, S, C>
where
    P: ValidatorNodeProvider + Send + Sync + 'static,
    S: Storage + Clone + Send + Sync + 'static,
    C: ClientContext<P> + Send + 'static,
    ViewError: From<S::ContextError>,
{
    async fn execute_system_operation(
        &self,
        system_operation: SystemOperation,
        chain_id: ChainId,
    ) -> Result<CryptoHash, Error> {
        let certificate = self
            .apply_client_command(&chain_id, move |mut client| {
                let operation = Operation::System(system_operation.clone());
                async move {
                    let result = client
                        .execute_operation(operation)
                        .await
                        .map_err(Error::from);
                    (result, client)
                }
            })
            .await?;
        Ok(certificate.hash())
    }

    /// Applies the given function to the chain client.
    /// Updates the wallet regardless of the outcome. As long as the function returns a round
    /// timeout, it will wait and retry.
    async fn apply_client_command<F, Fut, T>(
        &self,
        chain_id: &ChainId,
        mut f: F,
    ) -> Result<T, Error>
    where
        F: FnMut(OwnedMutexGuard<ChainClient<P, S>>) -> Fut,
        Fut: Future<
            Output = (
                Result<ClientOutcome<T>, Error>,
                OwnedMutexGuard<ChainClient<P, S>>,
            ),
        >,
    {
        loop {
            let mut client = self.clients.try_client_lock(chain_id).await?;
            let mut stream = client.subscribe().await?;
            let (result, mut client) = f(client).await;
            self.context.lock().await.update_wallet(&mut *client).await;
            let timeout = match result? {
                ClientOutcome::Committed(t) => return Ok(t),
                ClientOutcome::WaitForTimeout(timeout) => timeout,
            };
            drop(client);
            wait_for_next_round(&mut stream, timeout).await;
        }
    }
}

#[Object]
impl<P, S, C> MutationRoot<P, S, C>
where
    P: ValidatorNodeProvider + Send + Sync + 'static,
    <<P as ValidatorNodeProvider>::Node as ValidatorNode>::NotificationStream: Send,
    S: Storage + Clone + Send + Sync + 'static,
    C: ClientContext<P> + Send + 'static,
    ViewError: From<S::ContextError>,
{
    /// Processes the inbox and returns the lists of certificate hashes that were created, if any.
    async fn process_inbox(&self, chain_id: ChainId) -> Result<Vec<CryptoHash>, Error> {
        let mut hashes = Vec::new();
        loop {
            let mut client = self.clients.try_client_lock(&chain_id).await?;
            client.synchronize_from_validators().await?;
            let result = client.process_inbox().await;
            self.context.lock().await.update_wallet(&mut *client).await;
            let (certificates, maybe_timeout) = result?;
            hashes.extend(certificates.into_iter().map(|cert| cert.hash()));
            match maybe_timeout {
                None => return Ok(hashes),
                Some(timestamp) => {
                    let mut stream = client.subscribe().await?;
                    drop(client);
                    wait_for_next_round(&mut stream, timestamp).await;
                }
            }
        }
    }

    /// Retries the pending block that was unsuccessfully proposed earlier.
    async fn retry_pending_block(&self, chain_id: ChainId) -> Result<Option<CryptoHash>, Error> {
        let mut client = self.clients.try_client_lock(&chain_id).await?;
        let outcome = client.process_pending_block().await?;
        self.context.lock().await.update_wallet(&mut *client).await;
        match outcome {
            ClientOutcome::Committed(Some(certificate)) => Ok(Some(certificate.hash())),
            ClientOutcome::Committed(None) => Ok(None),
            ClientOutcome::WaitForTimeout(timeout) => Err(Error::from(format!(
                "Please try again at {}",
                timeout.timestamp
            ))),
        }
    }

    /// Transfers `amount` units of value from the given owner's account to the recipient.
    /// If no owner is given, try to take the units out of the unattributed account.
    async fn transfer(
        &self,
        chain_id: ChainId,
        owner: Option<Owner>,
        recipient: Recipient,
        amount: Amount,
        user_data: Option<UserData>,
    ) -> Result<CryptoHash, Error> {
        self.apply_client_command(&chain_id, move |mut client| {
            let user_data = user_data.clone();
            async move {
                let result = client
                    .transfer(owner, amount, recipient, user_data.unwrap_or_default())
                    .await
                    .map_err(Error::from)
                    .map(|outcome| outcome.map(|certificate| certificate.hash()));
                (result, client)
            }
        })
        .await
    }

    /// Claims `amount` units of value from the given owner's account in the remote
    /// `target` chain. Depending on its configuration, the `target` chain may refuse to
    /// process the message.
    #[allow(clippy::too_many_arguments)]
    async fn claim(
        &self,
        chain_id: ChainId,
        owner: Owner,
        target_id: ChainId,
        recipient: Recipient,
        amount: Amount,
        user_data: Option<UserData>,
    ) -> Result<CryptoHash, Error> {
        self.apply_client_command(&chain_id, move |mut client| {
            let user_data = user_data.clone();
            async move {
                let result = client
                    .claim(
                        owner,
                        target_id,
                        recipient,
                        amount,
                        user_data.unwrap_or_default(),
                    )
                    .await
                    .map_err(Error::from)
                    .map(|outcome| outcome.map(|certificate| certificate.hash()));
                (result, client)
            }
        })
        .await
    }

    /// Creates (or activates) a new chain by installing the given authentication key.
    /// This will automatically subscribe to the future committees created by `admin_id`.
    async fn open_chain(
        &self,
        chain_id: ChainId,
        public_key: PublicKey,
        balance: Option<Amount>,
    ) -> Result<ChainId, Error> {
        let ownership = ChainOwnership::single(public_key);
        let balance = balance.unwrap_or(Amount::ZERO);
        let message_id = self
            .apply_client_command(&chain_id, move |mut client| {
                let ownership = ownership.clone();
                async move {
                    let result = client
                        .open_chain(ownership, balance)
                        .await
                        .map_err(Error::from)
                        .map(|outcome| outcome.map(|(message_id, _)| message_id));
                    (result, client)
                }
            })
            .await?;
        Ok(ChainId::child(message_id))
    }

    /// Creates (or activates) a new chain by installing the given authentication keys.
    /// This will automatically subscribe to the future committees created by `admin_id`.
    #[allow(clippy::too_many_arguments)]
    async fn open_multi_owner_chain(
        &self,
        chain_id: ChainId,
        public_keys: Vec<PublicKey>,
        weights: Option<Vec<u64>>,
        multi_leader_rounds: Option<u32>,
        balance: Option<Amount>,
        #[graphql(desc = "The duration of the fast round, in milliseconds; default: no timeout")]
        fast_round_ms: Option<u64>,
        #[graphql(
            desc = "The duration of the first single-leader and all multi-leader rounds",
            default = 10_000
        )]
        base_timeout_ms: u64,
        #[graphql(
            desc = "The number of milliseconds by which the timeout increases after each \
                    single-leader round",
            default = 1_000
        )]
        timeout_increment_ms: u64,
        #[graphql(
            desc = "The age of an incoming tracked or protected message after which the \
                    validators start transitioning the chain to fallback mode, in milliseconds.",
            default = 86_400_000
        )]
        fallback_duration_ms: u64,
    ) -> Result<ChainId, Error> {
        let owners = if let Some(weights) = weights {
            if weights.len() != public_keys.len() {
                return Err(Error::new(format!(
                    "There are {} public keys but {} weights.",
                    public_keys.len(),
                    weights.len()
                )));
            }
            public_keys.into_iter().zip(weights).collect::<Vec<_>>()
        } else {
            public_keys
                .into_iter()
                .zip(iter::repeat(100))
                .collect::<Vec<_>>()
        };
        let multi_leader_rounds = multi_leader_rounds.unwrap_or(u32::MAX);
        let timeout_config = TimeoutConfig {
            fast_round_duration: fast_round_ms.map(TimeDelta::from_millis),
            base_timeout: TimeDelta::from_millis(base_timeout_ms),
            timeout_increment: TimeDelta::from_millis(timeout_increment_ms),
            fallback_duration: TimeDelta::from_millis(fallback_duration_ms),
        };
        let ownership = ChainOwnership::multiple(owners, multi_leader_rounds, timeout_config);
        let balance = balance.unwrap_or(Amount::ZERO);
        let message_id = self
            .apply_client_command(&chain_id, move |mut client| {
                let ownership = ownership.clone();
                async move {
                    let result = client
                        .open_chain(ownership, balance)
                        .await
                        .map_err(Error::from)
                        .map(|outcome| outcome.map(|(message_id, _)| message_id));
                    (result, client)
                }
            })
            .await?;
        Ok(ChainId::child(message_id))
    }

    /// Closes the chain.
    async fn close_chain(&self, chain_id: ChainId) -> Result<CryptoHash, Error> {
        let certificate = self
            .apply_client_command(&chain_id, |mut client| async move {
                let result = client.close_chain().await.map_err(Error::from);
                (result, client)
            })
            .await?;
        Ok(certificate.hash())
    }

    /// Changes the authentication key of the chain.
    async fn change_owner(
        &self,
        chain_id: ChainId,
        new_public_key: PublicKey,
    ) -> Result<CryptoHash, Error> {
        let operation = SystemOperation::ChangeOwnership {
            super_owners: vec![new_public_key],
            owners: Vec::new(),
            multi_leader_rounds: 2,
            timeout_config: TimeoutConfig::default(),
        };
        self.execute_system_operation(operation, chain_id).await
    }

    /// Changes the authentication key of the chain.
    #[allow(clippy::too_many_arguments)]
    async fn change_multiple_owners(
        &self,
        chain_id: ChainId,
        new_public_keys: Vec<PublicKey>,
        new_weights: Vec<u64>,
        multi_leader_rounds: u32,
        #[graphql(desc = "The duration of the fast round, in milliseconds; default: no timeout")]
        fast_round_ms: Option<u64>,
        #[graphql(
            desc = "The duration of the first single-leader and all multi-leader rounds",
            default = 10_000
        )]
        base_timeout_ms: u64,
        #[graphql(
            desc = "The number of milliseconds by which the timeout increases after each \
                    single-leader round",
            default = 1_000
        )]
        timeout_increment_ms: u64,
        #[graphql(
            desc = "The age of an incoming tracked or protected message after which the \
                    validators start transitioning the chain to fallback mode, in milliseconds.",
            default = 86_400_000
        )]
        fallback_duration_ms: u64,
    ) -> Result<CryptoHash, Error> {
        let operation = SystemOperation::ChangeOwnership {
            super_owners: Vec::new(),
            owners: new_public_keys.into_iter().zip(new_weights).collect(),
            multi_leader_rounds,
            timeout_config: TimeoutConfig {
                fast_round_duration: fast_round_ms.map(TimeDelta::from_millis),
                base_timeout: TimeDelta::from_millis(base_timeout_ms),
                timeout_increment: TimeDelta::from_millis(timeout_increment_ms),
                fallback_duration: TimeDelta::from_millis(fallback_duration_ms),
            },
        };
        self.execute_system_operation(operation, chain_id).await
    }

    /// Changes the application permissions configuration on this chain.
    async fn change_application_permissions(
        &self,
        chain_id: ChainId,
        close_chain: Vec<ApplicationId>,
        execute_operations: Option<Vec<ApplicationId>>,
    ) -> Result<CryptoHash, Error> {
        let operation = SystemOperation::ChangeApplicationPermissions(ApplicationPermissions {
            execute_operations,
            close_chain,
        });
        self.execute_system_operation(operation, chain_id).await
    }

    /// (admin chain only) Registers a new committee. This will notify the subscribers of
    /// the admin chain so that they can migrate to the new epoch (by accepting the
    /// notification as an "incoming message" in a next block).
    async fn create_committee(
        &self,
        chain_id: ChainId,
        epoch: Epoch,
        committee: Committee,
    ) -> Result<CryptoHash, Error> {
        let operation =
            SystemOperation::Admin(AdminOperation::CreateCommittee { epoch, committee });
        self.execute_system_operation(operation, chain_id).await
    }

    /// Subscribes to a system channel.
    async fn subscribe(
        &self,
        subscriber_chain_id: ChainId,
        publisher_chain_id: ChainId,
        channel: SystemChannel,
    ) -> Result<CryptoHash, Error> {
        let operation = SystemOperation::Subscribe {
            chain_id: publisher_chain_id,
            channel,
        };
        self.execute_system_operation(operation, subscriber_chain_id)
            .await
    }

    /// Unsubscribes from a system channel.
    async fn unsubscribe(
        &self,
        subscriber_chain_id: ChainId,
        publisher_chain_id: ChainId,
        channel: SystemChannel,
    ) -> Result<CryptoHash, Error> {
        let operation = SystemOperation::Unsubscribe {
            chain_id: publisher_chain_id,
            channel,
        };
        self.execute_system_operation(operation, subscriber_chain_id)
            .await
    }

    /// (admin chain only) Removes a committee. Once this message is accepted by a chain,
    /// blocks from the retired epoch will not be accepted until they are followed (hence
    /// re-certified) by a block certified by a recent committee.
    async fn remove_committee(&self, chain_id: ChainId, epoch: Epoch) -> Result<CryptoHash, Error> {
        let operation = SystemOperation::Admin(AdminOperation::RemoveCommittee { epoch });
        self.execute_system_operation(operation, chain_id).await
    }

    /// Publishes a new application bytecode.
    async fn publish_bytecode(
        &self,
        chain_id: ChainId,
        contract: Bytecode,
        service: Bytecode,
    ) -> Result<BytecodeId, Error> {
        self.apply_client_command(&chain_id, move |mut client| {
            let contract = contract.clone();
            let service = service.clone();
            async move {
                let result = client
                    .publish_bytecode(contract, service)
                    .await
                    .map_err(Error::from)
                    .map(|outcome| outcome.map(|(bytecode_id, _)| bytecode_id));
                (result, client)
            }
        })
        .await
    }

    /// Publishes a new blob.
    async fn publish_blob(&self, chain_id: ChainId, blob: Blob) -> Result<BlobId, Error> {
        self.apply_client_command(&chain_id, move |mut client| {
            let blob = blob.clone();
            async move {
                let result = client
                    .publish_blob(blob.into_hashed())
                    .await
                    .map_err(Error::from)
                    .map(|outcome| outcome.map(|(blob_id, _)| blob_id));
                (result, client)
            }
        })
        .await
    }

    /// Creates a new application.
    async fn create_application(
        &self,
        chain_id: ChainId,
        bytecode_id: BytecodeId,
        parameters: String,
        instantiation_argument: String,
        required_application_ids: Vec<UserApplicationId>,
    ) -> Result<ApplicationId, Error> {
        self.apply_client_command(&chain_id, move |mut client| {
            let parameters = parameters.as_bytes().to_vec();
            let instantiation_argument = instantiation_argument.as_bytes().to_vec();
            let required_application_ids = required_application_ids.clone();
            async move {
                let result = client
                    .create_application_untyped(
                        bytecode_id,
                        parameters,
                        instantiation_argument,
                        required_application_ids,
                    )
                    .await
                    .map_err(Error::from)
                    .map(|outcome| outcome.map(|(application_id, _)| application_id));
                (result, client)
            }
        })
        .await
    }

    /// Requests a `RegisterApplications` message from another chain so the application can be used
    /// on this one.
    async fn request_application(
        &self,
        chain_id: ChainId,
        application_id: UserApplicationId,
        target_chain_id: Option<ChainId>,
    ) -> Result<CryptoHash, Error> {
        loop {
            let mut client = self.clients.try_client_lock(&chain_id).await?;
            let result = client
                .request_application(application_id, target_chain_id)
                .await;
            self.context.lock().await.update_wallet(&mut *client).await;
            let timeout = match result? {
                ClientOutcome::Committed(certificate) => return Ok(certificate.hash()),
                ClientOutcome::WaitForTimeout(timeout) => timeout,
            };
            let mut stream = client.subscribe().await?;
            drop(client);
            wait_for_next_round(&mut stream, timeout).await;
        }
    }

    /// ResPeer::CheCko::Initialize offline wallet
    async fn wallet_init_without_keypair(
        &self,
        public_key: PublicKey,
        faucet_url: String,
        chain_id: ChainId,
        message_id: MessageId,
        with_other_chains: Vec<ChainId>,
    ) -> Result<ChainId, Error> {
        let faucet = cli_wrappers::Faucet::new(faucet_url);
        let validators = faucet.current_validators().await?;

        let state = WorkerState::new("Local node".to_string(), None, self.storage.clone())
            .with_allow_inactive_chains(true)
            .with_allow_messages_from_deprecated_epochs(true);
        let mut node_client = LocalNodeClient::new(state, Arc::new(Notifier::default()));
        let admin_chain_id = self.context.lock().await.wallet().genesis_admin_chain();

        let nodes = self
            .context
            .lock()
            .await
            .make_node_provider()
            .make_nodes_from_list(validators)?;
        let target_height = message_id.height.try_add_one()?;
        node_client
            .download_certificates(nodes, message_id.chain_id, target_height)
            .await
            .context("Failed to download parent chain")?;
        let certificate = node_client
            .certificate_for(&message_id)
            .await
            .context("could not find OpenChain message")?;
        let CertificateValue::ConfirmedBlock { executed_block, .. } = certificate.value() else {
            return Err(anyhow!(NodeServiceError::UnexpectedCertificate).into());
        };
        let Some(Message::System(SystemMessage::OpenChain(config))) = executed_block
            .message_by_id(&message_id)
            .map(|msg| &msg.message)
        else {
            return Err(anyhow!(NodeServiceError::NotOpenChainMessage).into());
        };
        if config.ownership.verify_owner(&Owner::from(public_key)) != Some(public_key) {
            return Err(anyhow!(
                "The chain with the ID returned by the faucet is not owned by you. \
                    Please make sure you are connecting to a genuine faucet."
            )
            .into());
        }
        self.context
            .lock()
            .await
            .wallet_mut()
            .assign_new_chain_to_public_key(public_key, chain_id, executed_block.block.timestamp)
            .context("could not assign the new chain")?;

        let chain_ids = with_other_chains
            .into_iter()
            .chain([admin_chain_id, chain_id]);

        let mut chains = HashMap::new();
        for chain_id in chain_ids {
            if chains.contains_key(&chain_id) {
                continue;
            }
            chains.insert(chain_id, self.storage.load_chain(chain_id).await?);
        }
        let (peg_chain_id, _) = chains
            .iter()
            .filter_map(|(chain_id, chain)| {
                let epoch = (*chain.execution_state.system.epoch.get())?;
                let is_admin = Some(*chain_id) == *chain.execution_state.system.admin_id.get();
                Some((*chain_id, (epoch, is_admin)))
            })
            .max_by_key(|(_, epoch)| *epoch)
            .context("no active chain found")?;
        let peg_chain = chains.remove(&peg_chain_id).unwrap();
        let committees = peg_chain.execution_state.system.committees.get();
        for (chain_id, chain) in &chains {
            let Some(hash) = chain.tip_state.get().block_hash else {
                continue;
            };
            let certificate = self.storage.read_certificate(hash).await?;
            let committee = committees
                .get(&certificate.value().epoch())
                .ok_or_else(|| anyhow!("tip of chain {chain_id} is outdated."))?;
            certificate.check(committee)?;
        }
        let config_hash = CryptoHash::new(self.context.lock().await.wallet().genesis_config());
        let maybe_epoch = peg_chain.execution_state.system.epoch.get();
        let epoch = maybe_epoch.context("missing epoch in peg chain")?.0;
        info!(
            "Initialized wallet based on data provided by the faucet.\n\
            The current epoch is {epoch}.\n\
            The genesis config hash is {config_hash}{}",
            if let Some(peg_hash) = peg_chain.tip_state.get().block_hash {
                format!("\nThe latest certificate on chain {peg_chain_id} is {peg_hash}.")
            } else {
                "".to_string()
            }
        );

        self.context
            .lock()
            .await
            .wallet_mut()
            .set_default_chain(chain_id)?;
        self.context.lock().await.save_wallet();

        ChainListener::run_with_chain_id(
            chain_id,
            self.clients.clone(),
            self.context.clone(),
            self.storage.clone(),
            self.config.clone(),
        );

        Ok(chain_id)
    }

    /// Submit pending block proposal signature
    async fn submit_block_signature(
        &self,
        chain_id: ChainId,
        height: BlockHeight,
        signature: Signature,
    ) -> Result<CryptoHash, Error> {
        let mut client = self.clients.try_client_lock(&chain_id).await?;
        let hash = client
            .submit_extenal_signed_block_proposal(height, signature)
            .await?
            .value
            .hash();
        self.context.lock().await.update_wallet(&mut *client).await;
        Ok(hash)
    }

    /// Transfers `amount` units of value from the given owner's account to the recipient.
    /// If no owner is given, try to take the units out of the unattributed account.
    /// Different from transfer, node service won't sign block in transfer_without_block_proposal
    async fn transfer_without_block_proposal(
        &self,
        from_chain_id: ChainId,
        from_public_key: Option<PublicKey>,
        to_chain_id: ChainId,
        to_public_key: Option<PublicKey>,
        amount: Amount,
        user_data: Option<UserData>,
    ) -> Result<ChainId, Error> {
        let from_owner = match from_public_key {
            Some(public_key) => Some(Owner::from(public_key)),
            _ => None,
        };
        let to_owner = match to_public_key {
            Some(public_key) => Some(Owner::from(public_key)),
            _ => None,
        };
        let mut client = self.clients.try_client_lock(&from_chain_id).await?;
        client
            .transfer_without_block_proposal(
                from_owner,
                amount,
                Recipient::Account(Account {
                    chain_id: to_chain_id,
                    owner: to_owner,
                }),
                user_data.unwrap_or_default(),
            )
            .await?;
        Ok(from_chain_id)
    }

    /// Requests a `RegisterApplications` message from another chain so the application can be used
    /// on this one.
    async fn request_application_without_block_proposal(
        &self,
        chain_id: ChainId,
        application_id: UserApplicationId,
        target_chain_id: Option<ChainId>,
    ) -> Result<UserApplicationId, Error> {
        let mut client = self.clients.try_client_lock(&chain_id).await?;
        client
            .request_application_without_block_proposal(application_id, target_chain_id)
            .await?;
        Ok(application_id)
    }
}

#[Object]
impl<P, S> QueryRoot<P, S>
where
    P: ValidatorNodeProvider + Send + Sync + 'static,
    S: Storage + Clone + Send + Sync + 'static,
    ViewError: From<S::ContextError>,
{
    async fn chain(&self, chain_id: ChainId) -> Result<ChainStateExtendedView<S::Context>, Error> {
        let client = self.clients.try_client_lock(&chain_id).await?;
        let view = client.chain_state_view().await?;
        Ok(ChainStateExtendedView::new(view))
    }

    async fn applications(&self, chain_id: ChainId) -> Result<Vec<ApplicationOverview>, Error> {
        let client = self.clients.try_client_lock(&chain_id).await?;
        let applications = client
            .chain_state_view()
            .await?
            .execution_state
            .list_applications()
            .await?;

        let overviews = applications
            .into_iter()
            .map(|(id, description)| ApplicationOverview::new(id, description, self.port, chain_id))
            .collect();

        Ok(overviews)
    }

    async fn chains(&self) -> Result<Chains, Error> {
        Ok(Chains {
            list: self.clients.0.lock().await.keys().cloned().collect(),
            default: self.default_chain,
        })
    }

    async fn block(
        &self,
        hash: Option<CryptoHash>,
        chain_id: ChainId,
    ) -> Result<Option<HashedCertificateValue>, Error> {
        let client = self.clients.try_client_lock(&chain_id).await?;
        let hash = match hash {
            Some(hash) => Some(hash),
            None => {
                let view = client.chain_state_view().await?;
                view.tip_state.get().block_hash
            }
        };
        if let Some(hash) = hash {
            let block = client.read_hashed_certificate_value(hash).await?;
            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    async fn blocks(
        &self,
        from: Option<CryptoHash>,
        chain_id: ChainId,
        limit: Option<u32>,
    ) -> Result<Vec<HashedCertificateValue>, Error> {
        let client = self.clients.try_client_lock(&chain_id).await?;
        let limit = limit.unwrap_or(10);
        let from = match from {
            Some(from) => Some(from),
            None => {
                let view = client.chain_state_view().await?;
                view.tip_state.get().block_hash
            }
        };
        if let Some(from) = from {
            let values = client
                .read_hashed_certificate_values_downward(from, limit)
                .await?;
            Ok(values)
        } else {
            Ok(vec![])
        }
    }

    /// Returns the version information on this node service.
    async fn version(&self) -> linera_version::VersionInfo {
        linera_version::VersionInfo::default()
    }

    /// Returns the pending message of the chain
    async fn pending_messages(&self, chain_id: ChainId) -> Result<Vec<IncomingMessage>, Error> {
        let mut client = self.clients.try_client_lock(&chain_id).await?;
        Ok(client.pending_messages().await?)
    }

    /// Returns the next raw block proposal
    async fn peek_candidate_raw_block_payload(
        &self,
        chain_id: ChainId,
    ) -> Result<Option<RawBlockProposalPayload>, Error> {
        let mut client = self.clients.try_client_lock(&chain_id).await?;
        match client.peek_candidate_block_proposal().await {
            Some(raw_block_proposal) => {
                let mut message = Vec::new();
                let outcome = raw_block_proposal
                    .validated
                    .as_ref()
                    .and_then(|certificate| certificate.value().executed_block())
                    .map(|executed_block| Cow::Borrowed(&executed_block.outcome));
                let proposal_payload = &ProposalPayload {
                    content: Cow::Borrowed(&raw_block_proposal.content),
                    outcome,
                };
                proposal_payload.write(&mut message);
                Ok(Some(RawBlockProposalPayload {
                    height: raw_block_proposal.content.block.height,
                    payload_bytes: message,
                }))
            }
            _ => Ok(None),
        }
    }

    /// Returns the balance of given owner
    async fn balance(
        &self,
        chain_id: ChainId,
        public_key: Option<PublicKey>,
    ) -> Result<Amount, Error> {
        let mut client = self.clients.try_client_lock(&chain_id).await?;
        Ok(match public_key {
            Some(public_key) => client.query_owner_balance(Owner::from(public_key)).await?,
            _ => client.query_balance().await?,
        })
    }

    /// Returns the balances of given owners
    async fn balances(
        &self,
        chain_ids: Vec<ChainId>,
        public_keys: Vec<PublicKey>,
    ) -> Result<HashMap<ChainId, ChainAccountBalances>, Error> {
        let mut chain_balances = HashMap::new();
        for chain_id in &chain_ids {
            let mut client = self.clients.try_client_lock(&chain_id).await?;
            let mut account_balances = HashMap::new();
            for public_key in &public_keys {
                account_balances.insert(
                    *public_key,
                    client.query_owner_balance(Owner::from(public_key)).await?,
                );
            }
            chain_balances.insert(
                *chain_id,
                ChainAccountBalances {
                    chain_balance: client.query_balance().await?,
                    account_balances,
                },
            );
        }
        Ok(chain_balances)
    }
}

// What follows is a hack to add a chain_id field to `ChainStateView` based on
// https://async-graphql.github.io/async-graphql/en/merging_objects.html

struct ChainStateViewExtension(ChainId);

#[Object]
impl ChainStateViewExtension {
    async fn chain_id(&self) -> ChainId {
        self.0
    }
}

#[derive(MergedObject)]
struct ChainStateExtendedView<C>(ChainStateViewExtension, Arc<ChainStateView<C>>)
where
    C: linera_views::common::Context + Clone + Send + Sync + 'static,
    ViewError: From<C::Error>,
    C::Extra: linera_execution::ExecutionRuntimeContext;

impl<C> ChainStateExtendedView<C>
where
    C: linera_views::common::Context + Clone + Send + Sync + 'static,
    ViewError: From<C::Error>,
    C::Extra: linera_execution::ExecutionRuntimeContext,
{
    fn new(view: Arc<ChainStateView<C>>) -> Self {
        Self(ChainStateViewExtension(view.chain_id()), view)
    }
}

#[derive(SimpleObject)]
pub struct ApplicationOverview {
    id: UserApplicationId,
    description: UserApplicationDescription,
    link: String,
}

impl ApplicationOverview {
    fn new(
        id: UserApplicationId,
        description: UserApplicationDescription,
        port: NonZeroU16,
        chain_id: ChainId,
    ) -> Self {
        Self {
            id,
            description,
            link: format!(
                "http://{}:{}/chains/{}/applications/{}",
                local_ip().unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                port.get(),
                chain_id,
                id
            ),
        }
    }
}

/// Given a parsed GraphQL query (or `ExecutableDocument`), returns the `OperationType`.
///
/// Errors:
///
/// If we have no `OperationType`s or the `OperationTypes` are heterogeneous, i.e. a query
/// was submitted with a `mutation` and `subscription`.
fn operation_type(document: &ExecutableDocument) -> Result<OperationType, NodeServiceError> {
    match &document.operations {
        DocumentOperations::Single(op) => Ok(op.node.ty),
        DocumentOperations::Multiple(ops) => {
            let mut op_types = ops.values().map(|v| v.node.ty);
            let first = op_types.next().ok_or(NodeServiceError::MissingOperation)?;
            op_types
                .all(|x| x == first)
                .then_some(first)
                .ok_or(NodeServiceError::HeterogeneousOperations)
        }
    }
}

/// Extracts the underlying byte vector from a serialized GraphQL response
/// from an application.
fn bytes_from_response(data: async_graphql::Value) -> Vec<Vec<u8>> {
    if let async_graphql::Value::Object(map) = data {
        map.values()
            .filter_map(|value| {
                if let async_graphql::Value::List(list) = value {
                    bytes_from_list(list)
                } else {
                    None
                }
            })
            .collect()
    } else {
        vec![]
    }
}

fn bytes_from_list(list: &[async_graphql::Value]) -> Option<Vec<u8>> {
    list.iter()
        .map(|item| {
            if let async_graphql::Value::Number(n) = item {
                n.as_u64().map(|n| n as u8)
            } else {
                None
            }
        })
        .collect()
}

/// The `NodeService` is a server that exposes a web-server to the client.
/// The node service is primarily used to explore the state of a chain in GraphQL.
pub struct NodeService<P, S, C> {
    clients: ChainClients<P, S>,
    config: ChainListenerConfig,
    port: NonZeroU16,
    default_chain: Option<ChainId>,
    storage: S,
    context: Arc<Mutex<C>>,
}

impl<P, S: Clone, C> Clone for NodeService<P, S, C> {
    fn clone(&self) -> Self {
        Self {
            clients: self.clients.clone(),
            config: self.config.clone(),
            port: self.port,
            default_chain: self.default_chain,
            storage: self.storage.clone(),
            context: self.context.clone(),
        }
    }
}

impl<P, S, C> NodeService<P, S, C>
where
    P: ValidatorNodeProvider + Send + Sync + 'static,
    <<P as ValidatorNodeProvider>::Node as ValidatorNode>::NotificationStream: Send,
    S: Storage + Clone + Send + Sync + 'static,
    C: ClientContext<P> + Send + 'static,
    ViewError: From<S::ContextError>,
{
    /// Creates a new instance of the node service given a client chain and a port.
    pub fn new(
        config: ChainListenerConfig,
        port: NonZeroU16,
        default_chain: Option<ChainId>,
        storage: S,
        context: C,
    ) -> Self {
        Self {
            clients: ChainClients::default(),
            config,
            port,
            default_chain,
            storage,
            context: Arc::new(Mutex::new(context)),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn schema(&self) -> Schema<QueryRoot<P, S>, MutationRoot<P, S, C>, SubscriptionRoot<P, S>> {
        Schema::build(
            QueryRoot {
                clients: self.clients.clone(),
                port: self.port,
                default_chain: self.default_chain,
            },
            MutationRoot {
                storage: self.storage.clone(),
                clients: self.clients.clone(),
                context: self.context.clone(),
                config: self.config.clone(),
            },
            SubscriptionRoot {
                clients: self.clients.clone(),
            },
        )
        .finish()
    }

    /// Runs the node service.
    pub async fn run(self) -> Result<(), anyhow::Error> {
        let port = self.port.get();
        let index_handler = axum::routing::get(util::graphiql).post(Self::index_handler);
        let application_handler =
            axum::routing::get(util::graphiql).post(Self::application_handler);
        let application_handler_without_block_proposal = axum::routing::get(util::graphiql)
            .post(Self::application_handler_without_block_proposal);

        let app = Router::new()
            .route("/", index_handler)
            .route(
                "/chains/:chain_id/applications/:application_id",
                application_handler,
            )
            .route(
                "/checko/chains/:chain_id/applications/:application_id",
                application_handler_without_block_proposal,
            )
            .route("/ready", axum::routing::get(|| async { "ready!" }))
            .route_service("/ws", GraphQLSubscription::new(self.schema()))
            .layer(Extension(self.clone()))
            // TODO(#551): Provide application authentication.
            .layer(CorsLayer::permissive());

        let ip_addr = local_ip().unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        info!("GraphiQL IDE: http://{}:{}", ip_addr, port);

        ChainListener::new(self.config, self.clients.clone())
            .run(self.context.clone(), self.storage.clone())
            .await;
        let serve_fut = axum::serve(
            tokio::net::TcpListener::bind(SocketAddr::from((ip_addr, port))).await?,
            app,
        );
        serve_fut.await?;

        Ok(())
    }

    /// Handles queries for user applications.
    async fn user_application_query(
        &self,
        application_id: UserApplicationId,
        request: &Request,
        chain_id: ChainId,
    ) -> Result<async_graphql::Response, NodeServiceError> {
        let bytes = serde_json::to_vec(&request)?;
        let query = Query::User {
            application_id,
            bytes,
        };
        let Some(client) = self.clients.client_lock(&chain_id).await else {
            return Err(NodeServiceError::UnknownChainId {
                chain_id: chain_id.to_string(),
            });
        };
        let response = client.query_application(query).await?;
        let user_response_bytes = match response {
            Response::System(_) => unreachable!("cannot get a system response for a user query"),
            Response::User(user) => user,
        };
        Ok(serde_json::from_slice(&user_response_bytes)?)
    }

    /// Handles mutations for user applications.
    async fn user_application_mutation(
        &self,
        application_id: UserApplicationId,
        request: &Request,
        chain_id: ChainId,
    ) -> Result<async_graphql::Response, NodeServiceError> {
        debug!("Request: {:?}", &request);
        let graphql_response = self
            .user_application_query(application_id, request, chain_id)
            .await?;
        if graphql_response.is_err() {
            let errors = graphql_response
                .errors
                .iter()
                .map(|e| e.to_string())
                .collect();
            return Err(NodeServiceError::ApplicationServiceError { errors });
        }
        debug!("Response: {:?}", &graphql_response);
        let bcs_bytes_list = bytes_from_response(graphql_response.data);
        if bcs_bytes_list.is_empty() {
            return Err(NodeServiceError::MalformedApplicationResponse);
        }
        let operations = bcs_bytes_list
            .into_iter()
            .map(|bytes| Operation::User {
                application_id,
                bytes,
            })
            .collect::<Vec<_>>();

        let hash = loop {
            let Some(mut client) = self.clients.client_lock(&chain_id).await else {
                return Err(NodeServiceError::UnknownChainId {
                    chain_id: chain_id.to_string(),
                });
            };
            let timeout = match client.execute_operations(operations.clone()).await? {
                ClientOutcome::Committed(certificate) => break certificate.value.hash(),
                ClientOutcome::WaitForTimeout(timeout) => timeout,
            };
            let mut stream = client.subscribe().await.map_err(|_| {
                ChainClientError::InternalError("Could not subscribe to the local node.")
            })?;
            drop(client);
            wait_for_next_round(&mut stream, timeout).await;
        };
        Ok(async_graphql::Response::new(hash.to_value()))
    }

    /// Executes a GraphQL query and generates a response for our `Schema`.
    async fn index_handler(service: Extension<Self>, request: GraphQLRequest) -> GraphQLResponse {
        service
            .0
            .schema()
            .execute(request.into_inner())
            .await
            .into()
    }

    /// Executes a GraphQL query against an application.
    /// Pattern matches on the `OperationType` of the query and routes the query
    /// accordingly.
    async fn application_handler(
        Path((chain_id, application_id)): Path<(String, String)>,
        service: Extension<Self>,
        request: GraphQLRequest,
    ) -> Result<GraphQLResponse, NodeServiceError> {
        let mut request = request.into_inner();

        let parsed_query = request.parsed_query()?;
        let operation_type = operation_type(parsed_query)?;

        let chain_id: ChainId = chain_id.parse().map_err(NodeServiceError::InvalidChainId)?;
        let application_id: UserApplicationId = application_id.parse()?;

        let response = match operation_type {
            OperationType::Query => {
                service
                    .0
                    .user_application_query(application_id, &request, chain_id)
                    .await?
            }
            OperationType::Mutation => {
                service
                    .0
                    .user_application_mutation(application_id, &request, chain_id)
                    .await?
            }
            OperationType::Subscription => return Err(NodeServiceError::UnsupportedQueryType),
        };

        Ok(response.into())
    }

    /// Handles mutations for user applications.
    async fn user_application_mutation_without_block_proposal(
        &self,
        application_id: UserApplicationId,
        request: &Request,
        chain_id: ChainId,
    ) -> Result<async_graphql::Response, NodeServiceError> {
        debug!("Request: {:?}", &request);
        let graphql_response = self
            .user_application_query(application_id, request, chain_id)
            .await?;
        if graphql_response.is_err() {
            let errors = graphql_response
                .errors
                .iter()
                .map(|e| e.to_string())
                .collect();
            return Err(NodeServiceError::ApplicationServiceError { errors });
        }
        debug!("Response: {:?}", &graphql_response);
        let bcs_bytes_list = bytes_from_response(graphql_response.data);
        if bcs_bytes_list.is_empty() {
            return Err(NodeServiceError::MalformedApplicationResponse);
        }
        let operations = bcs_bytes_list
            .into_iter()
            .map(|bytes| Operation::User {
                application_id,
                bytes,
            })
            .collect::<Vec<_>>();

        let Some(mut client) = self.clients.client_lock(&chain_id).await else {
            return Err(NodeServiceError::UnknownChainId {
                chain_id: chain_id.to_string(),
            });
        };
        client
            .execute_operations_without_block_proposal(operations.clone())
            .await?;
        Ok(async_graphql::Response::new(application_id.to_value()))
    }

    /// Executes a GraphQL query against an application.
    /// Pattern matches on the `OperationType` of the query and routes the query
    /// accordingly.
    async fn application_handler_without_block_proposal(
        Path((chain_id, application_id)): Path<(String, String)>,
        service: Extension<Self>,
        request: GraphQLRequest,
    ) -> Result<GraphQLResponse, NodeServiceError> {
        let mut request = request.into_inner();

        let parsed_query = request.parsed_query()?;
        let operation_type = operation_type(parsed_query)?;

        let chain_id: ChainId = chain_id.parse().map_err(NodeServiceError::InvalidChainId)?;
        let application_id: UserApplicationId = application_id.parse()?;

        let response = match operation_type {
            OperationType::Query => {
                service
                    .0
                    .user_application_query(application_id, &request, chain_id)
                    .await?
            }
            OperationType::Mutation => {
                service
                    .0
                    .user_application_mutation_without_block_proposal(
                        application_id,
                        &request,
                        chain_id,
                    )
                    .await?
            }
            OperationType::Subscription => return Err(NodeServiceError::UnsupportedQueryType),
        };

        Ok(response.into())
    }
}

/// Returns after the specified time or if we receive a notification that a new round has started.
pub async fn wait_for_next_round(stream: &mut NotificationStream, timeout: RoundTimeout) {
    let mut stream = stream.filter(|notification| match &notification.reason {
        Reason::NewBlock { height, .. } => *height >= timeout.next_block_height,
        Reason::NewRound { round, .. } => *round > timeout.current_round,
        Reason::NewIncomingMessage { .. } => false,
        Reason::NewRawBlock { height } => *height >= timeout.next_block_height,
    });
    future::select(
        Box::pin(stream.next()),
        Box::pin(tokio::time::sleep(
            timeout.timestamp.duration_since(Timestamp::now()),
        )),
    )
    .await;
}
