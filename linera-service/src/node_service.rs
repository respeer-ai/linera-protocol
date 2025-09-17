// Copyright (c) Zefchain Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    borrow::Cow, collections::HashMap, future::IntoFuture, iter, net::SocketAddr, num::NonZeroU16,
    sync::Arc,
};

use async_graphql::{
    futures_util::Stream, resolver_utils::ContainerType, Error, InputObject, MergedObject,
    OutputType, ScalarType, Schema, SimpleObject, Subscription,
};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse, GraphQLSubscription};
use axum::{
    body, extract::Path, http::StatusCode, response, response::IntoResponse, Extension, Router,
};
use futures::{lock::Mutex, Future, FutureExt as _};
use linera_base::{
    bcs_scalar,
    crypto::{AccountSignature, BcsSignable, CryptoError, CryptoHash},
    data_types::{
        Amount, ApplicationDescription, ApplicationPermissions, Blob, Bytecode, Epoch, TimeDelta,
    },
    doc_scalar, ensure,
    identifiers::{
        Account, AccountOwner, ApplicationId, ChainId, IndexAndEvent, ModuleId, StreamId,
    },
    ownership::{ChainOwnership, TimeoutConfig},
    vm::VmRuntime,
    BcsHexParseError,
};
use linera_chain::{
    data_types::{CandidateBlockMaterial, IncomingBundle},
    types::{ConfirmedBlock, GenericCertificate},
    ChainStateView,
};
use linera_client::chain_listener::{ChainListener, ChainListenerConfig, ClientContext};
use linera_core::{
    client::{ChainClient, ChainClientError},
    data_types::{ClientOutcome, UnsignedBlockProposal},
    worker::Notification,
};
use linera_execution::{
    committee::Committee, system::AdminOperation, Operation, Query, QueryOutcome, QueryResponse,
    SystemOperation,
};
use linera_sdk::linera_base_types::BlobContent;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use thiserror::Error as ThisError;
use tokio::sync::OwnedRwLockReadGuard;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;
use tracing::{debug, error, info, instrument, trace};

use crate::util;

#[derive(SimpleObject, Serialize, Deserialize, Clone)]
pub struct Chains {
    pub list: Vec<ChainId>,
    pub default: Option<ChainId>,
}

/// Our root GraphQL query type.
pub struct QueryRoot<C> {
    context: Arc<Mutex<C>>,
    port: NonZeroU16,
    default_chain: Option<ChainId>,
}

/// Our root GraphQL subscription type.
pub struct SubscriptionRoot<C> {
    context: Arc<Mutex<C>>,
}

/// Our root GraphQL mutation type.
pub struct MutationRoot<C>
where
    C: ClientContext,
{
    context: Arc<Mutex<C>>,

    chain_listener: Arc<Mutex<Option<ChainListener<C>>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockMaterial {
    operations: Vec<Operation>,
    blob_bytes: Vec<Vec<u8>>,
    candidate: CandidateBlockMaterial,
}

doc_scalar!(BlockMaterial, "Materials of a new block.");

#[derive(Debug, Clone, Serialize, Deserialize, InputObject)]
#[serde(rename_all = "camelCase")]
pub struct ChainOwners {
    chain_id: ChainId,
    owners: Vec<AccountOwner>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SimpleObject)]
#[serde(rename_all = "camelCase")]
pub struct Balances {
    chain_balance: Amount,
    owner_balances: HashMap<AccountOwner, Amount>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct SimulatedBlockMaterial {
    block_proposal: UnsignedBlockProposal,
    blob_bytes: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedBlock {
    unsigned_block_proposal: UnsignedBlockProposal,
    signature: AccountSignature,
    // If block contains PublishDataBlob, it should have blobs, too
    blob_bytes: Vec<Vec<u8>>,
}

doc_scalar!(
    SignedBlock,
    "A signed block which will be submitted to blockchain with its signature."
);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedBlockBcs {
    unsigned_block_proposal: UnsignedBlockProposal,
    signature: AccountSignature,
    // If block contains PublishDataBlob, it should have blobs, too
    blob_bytes: Vec<Vec<u8>>,
}

bcs_scalar!(
    SignedBlockBcs,
    "A signed block which will be submitted to blockchain with its signature."
);

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletInitializer {
    owner: AccountOwner,
    signature: AccountSignature,
    creator_chain_id: ChainId,
}

doc_scalar!(
    WalletInitializer,
    "Input parameters of wallet initialization."
);

#[derive(Debug, ThisError)]
enum NodeServiceError {
    #[error(transparent)]
    ChainClientError(#[from] ChainClientError),
    #[error(transparent)]
    BcsHexError(#[from] BcsHexParseError),
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    #[error("malformed chain ID: {0}")]
    InvalidChainId(CryptoError),
}

impl IntoResponse for NodeServiceError {
    fn into_response(self) -> response::Response {
        let tuple = match self {
            NodeServiceError::BcsHexError(e) => (StatusCode::BAD_REQUEST, vec![e.to_string()]),
            NodeServiceError::ChainClientError(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, vec![e.to_string()])
            }
            NodeServiceError::JsonError(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, vec![e.to_string()])
            }
            NodeServiceError::InvalidChainId(_) => (
                StatusCode::BAD_REQUEST,
                vec!["invalid chain ID".to_string()],
            ),
        };
        let tuple = (tuple.0, json!({"error": tuple.1}).to_string());
        tuple.into_response()
    }
}

#[Subscription]
impl<C> SubscriptionRoot<C>
where
    C: ClientContext + 'static,
{
    /// Subscribes to notifications from the specified chain.
    async fn notifications(
        &self,
        chain_id: ChainId,
    ) -> Result<impl Stream<Item = Notification>, Error> {
        let client = self.context.lock().await.make_chain_client(chain_id);
        Ok(client.subscribe()?)
    }
}

impl<C> MutationRoot<C>
where
    C: ClientContext,
{
    async fn execute_system_operation(
        &self,
        system_operation: SystemOperation,
        chain_id: ChainId,
    ) -> Result<CryptoHash, Error> {
        ensure!(cfg!(not(feature = "disable-native-rpc")), "Not supported");

        let certificate = self
            .apply_client_command(&chain_id, move |client| {
                let operation = Operation::system(system_operation.clone());
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
        F: FnMut(ChainClient<C::Environment>) -> Fut,
        Fut: Future<Output = (Result<ClientOutcome<T>, Error>, ChainClient<C::Environment>)>,
    {
        loop {
            let client = self.context.lock().await.make_chain_client(*chain_id);
            let mut stream = client.subscribe()?;
            let (result, client) = f(client).await;
            self.context.lock().await.update_wallet(&client).await?;
            let timeout = match result? {
                ClientOutcome::Committed(t) => return Ok(t),
                ClientOutcome::WaitForTimeout(timeout) => timeout,
            };
            drop(client);
            util::wait_for_next_round(&mut stream, timeout).await;
        }
    }

    async fn chain_initialized(
        &self,
        chain_id: ChainId,
        creator_chain_id: ChainId,
    ) -> Result<(), Error> {
        let client = self.context.lock().await.make_chain_client(chain_id);
        client.track_chain(chain_id);
        client.track_chain(creator_chain_id);
        client.retry_pending_outgoing_messages().await?;
        client.prepare_chain().await?;
        Ok(())
    }

    fn signature_owner(&self, signature: AccountSignature) -> AccountOwner {
        match signature {
            AccountSignature::Ed25519 { public_key, .. } => public_key.into(),
            AccountSignature::Secp256k1 { public_key, .. } => public_key.into(),
            AccountSignature::EvmSecp256k1 { address, .. } => AccountOwner::Address20(address),
        }
    }
}

#[async_graphql::Object(cache_control(no_cache))]
impl<C> MutationRoot<C>
where
    C: ClientContext + 'static,
{
    /// Processes the inbox and returns the lists of certificate hashes that were created, if any.
    async fn process_inbox(&self, chain_id: ChainId) -> Result<Vec<CryptoHash>, Error> {
        ensure!(cfg!(not(feature = "disable-native-rpc")), "Not supported");

        let mut hashes = Vec::new();
        loop {
            let client = self.context.lock().await.make_chain_client(chain_id);
            client.synchronize_from_validators().await?;
            let result = client.process_inbox_without_prepare().await;
            self.context.lock().await.update_wallet(&client).await?;
            let (certificates, maybe_timeout) = result?;
            hashes.extend(certificates.into_iter().map(|cert| cert.hash()));
            match maybe_timeout {
                None => return Ok(hashes),
                Some(timestamp) => {
                    let mut stream = client.subscribe()?;
                    drop(client);
                    util::wait_for_next_round(&mut stream, timestamp).await;
                }
            }
        }
    }

    /// Retries the pending block that was unsuccessfully proposed earlier.
    async fn retry_pending_block(&self, chain_id: ChainId) -> Result<Option<CryptoHash>, Error> {
        ensure!(cfg!(not(feature = "disable-native-rpc")), "Not supported");

        let client = self.context.lock().await.make_chain_client(chain_id);
        let outcome = client.process_pending_block().await?;
        self.context.lock().await.update_wallet(&client).await?;
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
    /// If no owner is given, try to take the units out of the chain account.
    async fn transfer(
        &self,
        chain_id: ChainId,
        owner: AccountOwner,
        recipient: Account,
        amount: Amount,
    ) -> Result<CryptoHash, Error> {
        ensure!(cfg!(not(feature = "disable-native-rpc")), "Not supported");

        self.apply_client_command(&chain_id, move |client| async move {
            let result = client
                .transfer(owner, amount, recipient)
                .await
                .map_err(Error::from)
                .map(|outcome| outcome.map(|certificate| certificate.hash()));
            (result, client)
        })
        .await
    }

    /// Claims `amount` units of value from the given owner's account in the remote
    /// `target` chain. Depending on its configuration, the `target` chain may refuse to
    /// process the message.
    async fn claim(
        &self,
        chain_id: ChainId,
        owner: AccountOwner,
        target_id: ChainId,
        recipient: Account,
        amount: Amount,
    ) -> Result<CryptoHash, Error> {
        ensure!(cfg!(not(feature = "disable-native-rpc")), "Not supported");

        self.apply_client_command(&chain_id, move |client| async move {
            let result = client
                .claim(owner, target_id, recipient, amount)
                .await
                .map_err(Error::from)
                .map(|outcome| outcome.map(|certificate| certificate.hash()));
            (result, client)
        })
        .await
    }

    /// Test if a data blob is readable from a transaction in the current chain.
    // TODO(#2490): Consider removing or renaming this.
    async fn read_data_blob(
        &self,
        chain_id: ChainId,
        hash: CryptoHash,
    ) -> Result<CryptoHash, Error> {
        self.apply_client_command(&chain_id, move |client| async move {
            let result = client
                .read_data_blob(hash)
                .await
                .map_err(Error::from)
                .map(|outcome| outcome.map(|certificate| certificate.hash()));
            (result, client)
        })
        .await
    }

    /// Creates (or activates) a new chain with the given owner.
    /// This will automatically subscribe to the future committees created by `admin_id`.
    async fn open_chain(
        &self,
        chain_id: ChainId,
        owner: AccountOwner,
        balance: Option<Amount>,
    ) -> Result<ChainId, Error> {
        ensure!(cfg!(not(feature = "disable-native-rpc")), "Not supported");

        let ownership = ChainOwnership::single(owner);
        let balance = balance.unwrap_or(Amount::ZERO);
        let description = self
            .apply_client_command(&chain_id, move |client| {
                let ownership = ownership.clone();
                async move {
                    let result = client
                        .open_chain(ownership, ApplicationPermissions::default(), balance)
                        .await
                        .map_err(Error::from)
                        .map(|outcome| outcome.map(|(chain_id, _)| chain_id));
                    (result, client)
                }
            })
            .await?;
        Ok(description.id())
    }

    /// Creates (or activates) a new chain by installing the given authentication keys.
    /// This will automatically subscribe to the future committees created by `admin_id`.
    #[expect(clippy::too_many_arguments)]
    async fn open_multi_owner_chain(
        &self,
        chain_id: ChainId,
        application_permissions: Option<ApplicationPermissions>,
        owners: Vec<AccountOwner>,
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
        ensure!(cfg!(not(feature = "disable-native-rpc")), "Not supported");

        let owners = if let Some(weights) = weights {
            if weights.len() != owners.len() {
                return Err(Error::new(format!(
                    "There are {} owners but {} weights.",
                    owners.len(),
                    weights.len()
                )));
            }
            owners.into_iter().zip(weights).collect::<Vec<_>>()
        } else {
            owners
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
        let description = self
            .apply_client_command(&chain_id, move |client| {
                let ownership = ownership.clone();
                let application_permissions = application_permissions.clone().unwrap_or_default();
                async move {
                    let result = client
                        .open_chain(ownership, application_permissions, balance)
                        .await
                        .map_err(Error::from)
                        .map(|outcome| outcome.map(|(chain_id, _)| chain_id));
                    (result, client)
                }
            })
            .await?;
        Ok(description.id())
    }

    /// Closes the chain. Returns `None` if it was already closed.
    async fn close_chain(&self, chain_id: ChainId) -> Result<Option<CryptoHash>, Error> {
        ensure!(cfg!(not(feature = "disable-native-rpc")), "Not supported");

        let maybe_cert = self
            .apply_client_command(&chain_id, |client| async move {
                let result = client.close_chain().await.map_err(Error::from);
                (result, client)
            })
            .await?;
        Ok(maybe_cert.as_ref().map(GenericCertificate::hash))
    }

    /// Changes the authentication key of the chain.
    async fn change_owner(
        &self,
        chain_id: ChainId,
        new_owner: AccountOwner,
    ) -> Result<CryptoHash, Error> {
        ensure!(cfg!(not(feature = "disable-native-rpc")), "Not supported");
        let operation = SystemOperation::ChangeOwnership {
            super_owners: vec![new_owner],
            owners: Vec::new(),
            multi_leader_rounds: 2,
            open_multi_leader_rounds: false,
            timeout_config: TimeoutConfig::default(),
        };
        self.execute_system_operation(operation, chain_id).await
    }

    /// Changes the authentication key of the chain.
    #[expect(clippy::too_many_arguments)]
    async fn change_multiple_owners(
        &self,
        chain_id: ChainId,
        new_owners: Vec<AccountOwner>,
        new_weights: Vec<u64>,
        multi_leader_rounds: u32,
        open_multi_leader_rounds: bool,
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
        ensure!(cfg!(not(feature = "disable-native-rpc")), "Not supported");

        let operation = SystemOperation::ChangeOwnership {
            super_owners: Vec::new(),
            owners: new_owners.into_iter().zip(new_weights).collect(),
            multi_leader_rounds,
            open_multi_leader_rounds,
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
    #[expect(clippy::too_many_arguments)]
    async fn change_application_permissions(
        &self,
        chain_id: ChainId,
        close_chain: Vec<ApplicationId>,
        execute_operations: Option<Vec<ApplicationId>>,
        mandatory_applications: Vec<ApplicationId>,
        change_application_permissions: Vec<ApplicationId>,
        call_service_as_oracle: Option<Vec<ApplicationId>>,
        make_http_requests: Option<Vec<ApplicationId>>,
    ) -> Result<CryptoHash, Error> {
        ensure!(cfg!(not(feature = "disable-native-rpc")), "Not supported");

        let operation = SystemOperation::ChangeApplicationPermissions(ApplicationPermissions {
            execute_operations,
            mandatory_applications,
            close_chain,
            change_application_permissions,
            call_service_as_oracle,
            make_http_requests,
        });
        self.execute_system_operation(operation, chain_id).await
    }

    /// (admin chain only) Registers a new committee. This will notify the subscribers of
    /// the admin chain so that they can migrate to the new epoch (by accepting the
    /// notification as an "incoming message" in a next block).
    async fn create_committee(
        &self,
        chain_id: ChainId,
        committee: Committee,
    ) -> Result<CryptoHash, Error> {
        ensure!(cfg!(not(feature = "disable-native-rpc")), "Not supported");

        Ok(self
            .apply_client_command(&chain_id, move |client| {
                let committee = committee.clone();
                async move {
                    let result = client
                        .stage_new_committee(committee)
                        .await
                        .map_err(Error::from);
                    (result, client)
                }
            })
            .await?
            .hash())
    }

    /// (admin chain only) Removes a committee. Once this message is accepted by a chain,
    /// blocks from the retired epoch will not be accepted until they are followed (hence
    /// re-certified) by a block certified by a recent committee.
    async fn remove_committee(&self, chain_id: ChainId, epoch: Epoch) -> Result<CryptoHash, Error> {
        ensure!(cfg!(not(feature = "disable-native-rpc")), "Not supported");

        let operation = SystemOperation::Admin(AdminOperation::RemoveCommittee { epoch });
        self.execute_system_operation(operation, chain_id).await
    }

    /// Publishes a new application module.
    async fn publish_module(
        &self,
        chain_id: ChainId,
        contract: Bytecode,
        service: Bytecode,
        vm_runtime: VmRuntime,
    ) -> Result<ModuleId, Error> {
        ensure!(cfg!(not(feature = "disable-native-rpc")), "Not supported");

        self.apply_client_command(&chain_id, move |client| {
            let contract = contract.clone();
            let service = service.clone();
            async move {
                let result = client
                    .publish_module(contract, service, vm_runtime)
                    .await
                    .map_err(Error::from)
                    .map(|outcome| outcome.map(|(module_id, _)| module_id));
                (result, client)
            }
        })
        .await
    }

    /// Publishes a new data blob.
    async fn publish_data_blob(
        &self,
        chain_id: ChainId,
        bytes: Vec<u8>,
    ) -> Result<CryptoHash, Error> {
        ensure!(cfg!(not(feature = "disable-native-rpc")), "Not supported");

        self.apply_client_command(&chain_id, |client| {
            let bytes = bytes.clone();
            async move {
                let result = client.publish_data_blob(bytes).await.map_err(Error::from);
                (result, client)
            }
        })
        .await
        .map(|_| CryptoHash::new(&BlobContent::new_data(bytes)))
    }

    /// Creates a new application.
    async fn create_application(
        &self,
        chain_id: ChainId,
        module_id: ModuleId,
        parameters: String,
        instantiation_argument: String,
        required_application_ids: Vec<ApplicationId>,
    ) -> Result<ApplicationId, Error> {
        ensure!(cfg!(not(feature = "disable-native-rpc")), "Not supported");

        self.apply_client_command(&chain_id, move |client| {
            let parameters = parameters.as_bytes().to_vec();
            let instantiation_argument = instantiation_argument.as_bytes().to_vec();
            let required_application_ids = required_application_ids.clone();
            async move {
                let result = client
                    .create_application_untyped(
                        module_id,
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

    /// ResPeer::CheCko::Initialize offline wallet
    async fn wallet_init_without_secret_key(
        &self,
        chain_id: ChainId,
        initializer: WalletInitializer,
    ) -> Result<ChainId, Error> {
        ensure!(cfg!(feature = "enable-wallet-rpc"), "Not supported");

        let WalletInitializer {
            owner,
            signature,
            creator_chain_id,
        } = initializer;

        #[derive(Debug, Serialize, Deserialize)]
        struct Nonce(ChainId);
        impl BcsSignable<'_> for Nonce {}

        ensure!(
            owner == self.signature_owner(signature),
            "Invalid signature"
        );

        tracing::info!("Verifing signature ...");
        let nonce = Nonce(creator_chain_id);
        signature.verify(&nonce)?;

        tracing::info!("Assigning new chain to public key ...");
        // Public key must already be added before claim new chain
        self.context
            .lock()
            .await
            .assign_new_chain_to_owner(chain_id, owner)
            .await?;

        tracing::info!("Setting default chain with public key ...");
        self.context
            .lock()
            .await
            .set_owner_default_chain(owner, chain_id)
            .await?;
        self.context.lock().await.save_wallet().await?;

        tracing::info!("Running chain {}", chain_id);
        self.chain_listener
            .lock()
            .await
            .take()
            .unwrap()
            .run_with_chain_id(chain_id)
            .await?;

        tokio::task::yield_now().await;
        std::thread::sleep(std::time::Duration::from_millis(2000));

        tracing::info!("Finalizing initialization ...");
        self.chain_initialized(chain_id, creator_chain_id).await?;

        tracing::info!("Initialized chain {}", chain_id);

        Ok(chain_id)
    }

    /// Submit block proposal with signature
    async fn submit_signed_block(
        &self,
        chain_id: ChainId,
        block: SignedBlock,
    ) -> Result<CryptoHash, Error> {
        ensure!(cfg!(feature = "enable-wallet-rpc"), "Not supported");

        let client = self.context.lock().await.make_chain_client(chain_id);

        let SignedBlock {
            unsigned_block_proposal,
            signature,
            blob_bytes,
        } = block;

        let hash = client
            .submit_external_signed_block_proposal_and_signature(
                unsigned_block_proposal,
                signature,
                blob_bytes
                    .into_iter()
                    .map(|bytes| Blob::new_data(bytes))
                    .collect(),
            )
            .await?
            .value()
            .inner()
            .hash();
        self.context.lock().await.update_wallet(&client).await?;
        Ok(hash)
    }

    /// Submit block proposal with signature
    async fn submit_signed_block_bcs(
        &self,
        chain_id: ChainId,
        block: SignedBlockBcs,
    ) -> Result<CryptoHash, Error> {
        ensure!(cfg!(feature = "enable-wallet-rpc"), "Not supported");

        let client = self.context.lock().await.make_chain_client(chain_id);

        let SignedBlockBcs {
            unsigned_block_proposal,
            signature,
            blob_bytes,
        } = block;

        let hash = client
            .submit_external_signed_block_proposal_and_signature(
                unsigned_block_proposal,
                signature,
                blob_bytes
                    .into_iter()
                    .map(|bytes| Blob::new_data(bytes))
                    .collect(),
            )
            .await?
            .value()
            .inner()
            .hash();
        self.context.lock().await.update_wallet(&client).await?;
        Ok(hash)
    }

    /// Calculate block execution state hash
    async fn simulate_execute_block(
        &self,
        chain_id: ChainId,
        block_material: BlockMaterial,
    ) -> Result<Option<SimulatedBlockMaterial>, Error> {
        ensure!(cfg!(feature = "enable-wallet-rpc"), "Not supported");

        let BlockMaterial {
            operations,
            blob_bytes,
            candidate,
        } = block_material;
        let CandidateBlockMaterial {
            incoming_bundles,
            local_time,
            ..
        } = candidate;

        let client = self.context.lock().await.make_chain_client(chain_id);

        let bundles: Vec<_> = incoming_bundles
            .iter()
            .map(|bundle| bundle.clone())
            .collect();
        let blobs: Vec<_> = blob_bytes.into_iter().map(Blob::new_data).collect();

        // TODO: Should we consider about the proposal blobs?
        let Some(block_proposal) = client
            .simulate_execute_block(operations, bundles, blobs.clone(), local_time)
            .await?
        else {
            // Finalizing last block, waiting for a moment
            return Ok(None);
        };
        let blob_bytes = blobs
            .into_iter()
            .map(|blob| blob.bytes().to_vec())
            .collect();
        Ok(Some(SimulatedBlockMaterial {
            block_proposal,
            blob_bytes,
        }))
    }
}

#[async_graphql::Object(cache_control(no_cache))]
impl<C> QueryRoot<C>
where
    C: ClientContext + 'static,
{
    async fn chain(
        &self,
        chain_id: ChainId,
    ) -> Result<
        ChainStateExtendedView<<C::Environment as linera_core::Environment>::StorageContext>,
        Error,
    > {
        let client = self.context.lock().await.make_chain_client(chain_id);
        let view = client.chain_state_view().await?;
        Ok(ChainStateExtendedView::new(view))
    }

    async fn applications(&self, chain_id: ChainId) -> Result<Vec<ApplicationOverview>, Error> {
        let client = self.context.lock().await.make_chain_client(chain_id);
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
            list: self.context.lock().await.wallet().chain_ids(),
            default: self.default_chain,
        })
    }

    async fn block(
        &self,
        hash: Option<CryptoHash>,
        chain_id: ChainId,
    ) -> Result<Option<ConfirmedBlock>, Error> {
        let client = self.context.lock().await.make_chain_client(chain_id);
        let hash = match hash {
            Some(hash) => Some(hash),
            None => {
                let view = client.chain_state_view().await?;
                view.tip_state.get().block_hash
            }
        };
        if let Some(hash) = hash {
            let block = client.read_confirmed_block(hash).await?;
            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    async fn events_from_index(
        &self,
        chain_id: ChainId,
        stream_id: StreamId,
        start_index: u32,
    ) -> Result<Vec<IndexAndEvent>, Error> {
        Ok(self
            .context
            .lock()
            .await
            .make_chain_client(chain_id)
            .events_from_index(stream_id, start_index)
            .await?)
    }

    async fn blocks(
        &self,
        from: Option<CryptoHash>,
        chain_id: ChainId,
        limit: Option<u32>,
    ) -> Result<Vec<ConfirmedBlock>, Error> {
        let client = self.context.lock().await.make_chain_client(chain_id);
        let limit = limit.unwrap_or(10);
        let from = match from {
            Some(from) => Some(from),
            None => {
                let view = client.chain_state_view().await?;
                view.tip_state.get().block_hash
            }
        };
        let Some(from) = from else {
            return Ok(vec![]);
        };
        let mut hash = Some(from);
        let mut values = Vec::new();
        for _ in 0..limit {
            let Some(next_hash) = hash else {
                break;
            };
            let value = client.read_confirmed_block(next_hash).await?;
            hash = value.block().header.previous_block_hash;
            values.push(value);
        }
        Ok(values)
    }

    /// Returns the version information on this node service.
    async fn version(&self) -> linera_version::VersionInfo {
        linera_version::VersionInfo::default()
    }

    /// Returns the pending message of the chain
    async fn pending_messages(&self, chain_id: ChainId) -> Result<Vec<IncomingBundle>, Error> {
        let client = self.context.lock().await.make_chain_client(chain_id);
        Ok(client.pending_message_bundles().await?)
    }

    /// Returns block material of the chain
    async fn block_material(
        &self,
        chain_id: ChainId,
        max_pending_messages: usize,
    ) -> Result<CandidateBlockMaterial, Error> {
        let client = self.context.lock().await.make_chain_client(chain_id);

        let incoming_bundles = client.pending_message_bundles().await?;
        let local_time = client.next_timestamp(&incoming_bundles, client.block_time().await?);
        let round = client.block_round().await?;

        let incoming_bundles = if incoming_bundles.len() > max_pending_messages {
            incoming_bundles[..max_pending_messages].to_vec()
        } else {
            incoming_bundles
        };

        Ok(CandidateBlockMaterial {
            incoming_bundles,
            local_time,
            round,
        })
    }

    /// Returns the balance of given owner
    async fn balance(
        &self,
        chain_id: ChainId,
        owner: Option<AccountOwner>,
    ) -> Result<Amount, Error> {
        let client = self.context.lock().await.make_chain_client(chain_id);
        Ok(match owner {
            Some(owner) => client.query_owner_balance(owner).await?,
            _ => client.query_balance().await?,
        })
    }

    /// Returns the balances of given owners
    async fn balances(
        &self,
        chain_owners: Vec<ChainOwners>,
    ) -> Result<HashMap<ChainId, Balances>, Error> {
        ensure!(cfg!(feature = "enable-wallet-rpc"), "Not supported");

        let mut chain_balances = HashMap::new();
        for chain in chain_owners {
            let client = self.context.lock().await.make_chain_client(chain.chain_id);
            let mut owner_balances = HashMap::new();
            for owner in chain.owners {
                owner_balances.insert(owner, client.query_owner_balance(owner).await?);
            }
            chain_balances.insert(
                chain.chain_id,
                Balances {
                    chain_balance: client.query_balance().await?,
                    owner_balances,
                },
            );
        }
        Ok(chain_balances)
    }

    /// Returns the maintained chains of given owner
    async fn owner_chains(&self, owner: AccountOwner) -> Result<Chains, Error> {
        let chain_ids = self.context.lock().await.wallet().owner_chain_ids(owner);
        let default_chain = self
            .context
            .lock()
            .await
            .wallet()
            .owner_default_chain(owner);

        Ok(Chains {
            list: chain_ids,
            default: default_chain,
        })
    }
}

// What follows is a hack to add a chain_id field to `ChainStateView` based on
// https://async-graphql.github.io/async-graphql/en/merging_objects.html

struct ChainStateViewExtension(ChainId);

#[async_graphql::Object(cache_control(no_cache))]
impl ChainStateViewExtension {
    async fn chain_id(&self) -> ChainId {
        self.0
    }
}

#[derive(MergedObject)]
struct ChainStateExtendedView<C>(ChainStateViewExtension, ReadOnlyChainStateView<C>)
where
    C: linera_views::context::Context + Clone + Send + Sync + 'static,
    C::Extra: linera_execution::ExecutionRuntimeContext;

/// A wrapper type that allows proxying GraphQL queries to a [`ChainStateView`] that's behind an
/// [`OwnedRwLockReadGuard`].
pub struct ReadOnlyChainStateView<C>(OwnedRwLockReadGuard<ChainStateView<C>>)
where
    C: linera_views::context::Context + Clone + Send + Sync + 'static;

impl<C> ContainerType for ReadOnlyChainStateView<C>
where
    C: linera_views::context::Context + Clone + Send + Sync + 'static,
{
    async fn resolve_field(
        &self,
        context: &async_graphql::Context<'_>,
    ) -> async_graphql::ServerResult<Option<async_graphql::Value>> {
        self.0.resolve_field(context).await
    }
}

impl<C> OutputType for ReadOnlyChainStateView<C>
where
    C: linera_views::context::Context + Clone + Send + Sync + 'static,
{
    fn type_name() -> Cow<'static, str> {
        ChainStateView::<C>::type_name()
    }

    fn create_type_info(registry: &mut async_graphql::registry::Registry) -> String {
        ChainStateView::<C>::create_type_info(registry)
    }

    async fn resolve(
        &self,
        context: &async_graphql::ContextSelectionSet<'_>,
        field: &async_graphql::Positioned<async_graphql::parser::types::Field>,
    ) -> async_graphql::ServerResult<async_graphql::Value> {
        self.0.resolve(context, field).await
    }
}

impl<C> ChainStateExtendedView<C>
where
    C: linera_views::context::Context + Clone + Send + Sync + 'static,
    C::Extra: linera_execution::ExecutionRuntimeContext,
{
    fn new(view: OwnedRwLockReadGuard<ChainStateView<C>>) -> Self {
        Self(
            ChainStateViewExtension(view.chain_id()),
            ReadOnlyChainStateView(view),
        )
    }
}

#[derive(SimpleObject)]
pub struct ApplicationOverview {
    id: ApplicationId,
    description: ApplicationDescription,
    link: String,
}

impl ApplicationOverview {
    fn new(
        id: ApplicationId,
        description: ApplicationDescription,
        port: NonZeroU16,
        chain_id: ChainId,
    ) -> Self {
        Self {
            id,
            description,
            link: format!(
                "http://localhost:{}/chains/{}/applications/{}",
                port.get(),
                chain_id,
                id
            ),
        }
    }
}

/// The `NodeService` is a server that exposes a web-server to the client.
/// The node service is primarily used to explore the state of a chain in GraphQL.
pub struct NodeService<C>
where
    C: ClientContext + 'static,
{
    config: ChainListenerConfig,
    port: NonZeroU16,
    default_chain: Option<ChainId>,
    context: Arc<Mutex<C>>,

    chain_listener: Arc<Mutex<Option<ChainListener<C>>>>,
}

impl<C> Clone for NodeService<C>
where
    C: ClientContext + 'static,
{
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            port: self.port,
            default_chain: self.default_chain,
            context: Arc::clone(&self.context),

            chain_listener: Arc::clone(&self.chain_listener),
        }
    }
}

impl<C> NodeService<C>
where
    C: ClientContext,
{
    /// Creates a new instance of the node service given a client chain and a port.
    pub async fn new(
        config: ChainListenerConfig,
        port: NonZeroU16,
        default_chain: Option<ChainId>,
        context: C,
        #[cfg(not(feature = "fake-chain-listener"))] cancellation_token: CancellationToken,
        #[cfg(feature = "fake-chain-listener")] _cancellation_token: CancellationToken,
    ) -> Self {
        let context = Arc::new(Mutex::new(context));

        #[cfg(not(feature = "fake-chain-listener"))]
        let storage = context.lock().await.storage().clone();

        Self {
            config: config.clone(),
            port,
            default_chain,
            context: Arc::clone(&context),

            #[cfg(not(feature = "fake-chain-listener"))]
            chain_listener: Arc::new(Mutex::new(Some(ChainListener::new(
                config,
                Arc::clone(&context),
                storage,
                cancellation_token,
            )))),
            #[cfg(feature = "fake-chain-listener")]
            chain_listener: Arc::new(Mutex::new(None)),
        }
    }

    pub fn schema(&self) -> Schema<QueryRoot<C>, MutationRoot<C>, SubscriptionRoot<C>> {
        Schema::build(
            QueryRoot {
                context: Arc::clone(&self.context),
                port: self.port,
                default_chain: self.default_chain,
            },
            MutationRoot {
                context: Arc::clone(&self.context),

                chain_listener: Arc::clone(&self.chain_listener),
            },
            SubscriptionRoot {
                context: Arc::clone(&self.context),
            },
        )
        .finish()
    }

    /// Runs the node service.
    #[instrument(name = "node_service", level = "info", skip_all, fields(port = ?self.port))]
    pub async fn run(self, _cancellation_token: CancellationToken) -> Result<(), anyhow::Error> {
        let port = self.port.get();
        let index_handler = axum::routing::get(util::graphiql).post(Self::index_handler);
        let application_handler =
            axum::routing::get(util::graphiql).post(Self::application_handler);
        let blob_handler = axum::routing::get(Self::blob_handler);
        let blob_image_handler = axum::routing::get(Self::blob_image_handler);
        let blob_html_handler = axum::routing::get(Self::blob_html_handler);
        let blob_video_handler = axum::routing::get(Self::blob_video_handler);

        let app = Router::new()
            .route("/", index_handler)
            .route(
                "/chains/{chain_id}/applications/{application_id}",
                application_handler,
            )
            .route(
                "/chains/{chain_id}/applications/{application_id}/contents/{blob_hash}",
                blob_handler,
            )
            .route(
                "/chains/{chain_id}/applications/{application_id}/images/{blob_hash}",
                blob_image_handler,
            )
            .route(
                "/chains/{chain_id}/applications/{application_id}/htmls/{blob_hash}",
                blob_html_handler,
            )
            .route(
                "/chains/{chain_id}/applications/{application_id}/videos/{blob_hash}",
                blob_video_handler,
            )
            .route("/ready", axum::routing::get(|| async { "ready!" }))
            .route_service("/ws", GraphQLSubscription::new(self.schema()))
            .layer(Extension(self.clone()))
            // TODO(#551): Provide application authentication.
            .layer(CorsLayer::permissive());

        info!("GraphiQL IDE: http://localhost:{}", port);

        let chain_listener = self
            .chain_listener
            .lock()
            .await
            .take()
            .unwrap()
            .run()
            .await?;

        let mut chain_listener = Box::pin(chain_listener).fuse();
        let tcp_listener =
            tokio::net::TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))).await?;
        let server = axum::serve(tcp_listener, app).into_future();
        futures::select! {
            result = chain_listener => result?,
            result = Box::pin(server).fuse() => result?,
        };

        Ok(())
    }

    /// Handles service queries for user applications (including mutations).
    async fn handle_service_request(
        &self,
        application_id: ApplicationId,
        request: Vec<u8>,
        chain_id: ChainId,
    ) -> Result<Vec<u8>, NodeServiceError> {
        let QueryOutcome {
            response,
            operations,
        } = self
            .query_user_application(application_id, request, chain_id)
            .await?;
        if operations.is_empty() {
            return Ok(response);
        }

        trace!("Query requested a new block with operations: {operations:?}");
        let client = self.context.lock().await.make_chain_client(chain_id);
        let hash = loop {
            let timeout = match client
                .execute_operations(operations.clone(), vec![])
                .await?
            {
                ClientOutcome::Committed(certificate) => break certificate.hash(),
                ClientOutcome::WaitForTimeout(timeout) => timeout,
            };
            let mut stream = client.subscribe().map_err(|_| {
                ChainClientError::InternalError("Could not subscribe to the local node.")
            })?;
            util::wait_for_next_round(&mut stream, timeout).await;
        };
        let response = async_graphql::Response::new(hash.to_value());
        Ok(serde_json::to_vec(&response)?)
    }

    /// Queries a user application, returning the raw [`QueryOutcome`].
    async fn query_user_application(
        &self,
        application_id: ApplicationId,
        bytes: Vec<u8>,
        chain_id: ChainId,
    ) -> Result<QueryOutcome<Vec<u8>>, NodeServiceError> {
        let query = Query::User {
            application_id,
            bytes,
        };
        let client = self.context.lock().await.make_chain_client(chain_id);
        let QueryOutcome {
            response,
            operations,
        } = client.query_application(query).await?;
        match response {
            QueryResponse::System(_) => {
                unreachable!("cannot get a system response for a user query")
            }
            QueryResponse::User(user_response_bytes) => Ok(QueryOutcome {
                response: user_response_bytes,
                operations,
            }),
        }
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

    async fn fetch_blob(
        chain_id: String,
        application_id: String,
        blob_hash: String,
        service: Extension<Self>,
    ) -> Result<Vec<u8>, NodeServiceError> {
        let chain_id: ChainId = chain_id.parse().map_err(NodeServiceError::InvalidChainId)?;
        let application_id: ApplicationId = application_id.parse()?;
        let request =
            format!("{{ \"query\": \" query {{ fetch(blobHash: \\\"{blob_hash}\\\") }}\" }}",);

        let _response = service
            .0
            .handle_service_request(application_id, request.into_bytes(), chain_id)
            .await?;
        let _response: JsonValue = serde_json::from_slice(&_response).unwrap();
        let _response: Vec<u8> =
            serde_json::from_value(_response.get("data").unwrap().get("fetch").unwrap().clone())
                .unwrap();
        Ok(_response)
    }

    async fn blob_handler(
        Path((chain_id, application_id, blob_hash)): Path<(String, String, String)>,
        service: Extension<Self>,
    ) -> Result<response::Response, NodeServiceError> {
        let _response = Self::fetch_blob(chain_id, application_id, blob_hash, service).await?;

        Ok(response::Response::builder()
            .status(StatusCode::OK)
            .body(body::Body::from(_response))
            .unwrap())
    }

    async fn blob_image_handler(
        Path((chain_id, application_id, blob_hash)): Path<(String, String, String)>,
        service: Extension<Self>,
    ) -> Result<response::Response, NodeServiceError> {
        let _response = Self::fetch_blob(chain_id, application_id, blob_hash, service).await?;

        Ok(response::Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "image/*")
            .body(body::Body::from(_response))
            .unwrap())
    }

    async fn blob_html_handler(
        Path((chain_id, application_id, blob_hash)): Path<(String, String, String)>,
        service: Extension<Self>,
    ) -> Result<impl IntoResponse, NodeServiceError> {
        let _response = Self::fetch_blob(chain_id, application_id, blob_hash, service).await?;

        Ok(response::Html(_response))
    }

    async fn blob_video_handler(
        Path((chain_id, application_id, blob_hash)): Path<(String, String, String)>,
        service: Extension<Self>,
    ) -> Result<response::Response, NodeServiceError> {
        let _response = Self::fetch_blob(chain_id, application_id, blob_hash, service).await?;

        Ok(response::Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "video/*")
            .body(body::Body::from(_response))
            .unwrap())
    }

    /// Executes a GraphQL query against an application.
    /// Pattern matches on the `OperationType` of the query and routes the query
    /// accordingly.
    async fn application_handler(
        Path((chain_id, application_id)): Path<(String, String)>,
        service: Extension<Self>,
        request: String,
    ) -> Result<Vec<u8>, NodeServiceError> {
        let chain_id: ChainId = chain_id.parse().map_err(NodeServiceError::InvalidChainId)?;
        let application_id: ApplicationId = application_id.parse()?;

        debug!(
            "Processing request for application {application_id} on chain {chain_id}:\n{:?}",
            &request
        );
        let response = service
            .0
            .handle_service_request(application_id, request.into_bytes(), chain_id)
            .await?;

        Ok(response)
    }
}
