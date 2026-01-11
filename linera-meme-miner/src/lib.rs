use std::sync::Arc;

use futures::{lock::Mutex, stream::StreamExt, FutureExt as _};
use linera_base::identifiers::{ApplicationId, ChainId};
use linera_client::chain_listener::{ChainListener, ChainListenerConfig, ClientContext};
use linera_core::Wallet;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

pub struct MemeMiner<C>
where
    C: ClientContext,
{
    context: Arc<Mutex<C>>,
    storage: <C::Environment as linera_core::Environment>::Storage,

    /// Meme proxy application id to register miner and get new meme chains
    meme_proxy_application_id: ApplicationId,
    new_block_notifier: Arc<Notify>,
    pub chain_listener_config: ChainListenerConfig,
}

impl<C> MemeMiner<C>
where
    C: ClientContext + 'static,
{
    pub async fn new(
        meme_proxy_application_id: ApplicationId,
        context: C,
        mut chain_listener_config: ChainListenerConfig,
    ) -> Self {
        // Check chain and owner in wallet, if chain is not available, request chain
        let owned_chain_ids: Vec<ChainId> = context
            .wallet()
            .owned_chain_ids()
            .map(|result| result.unwrap())
            .collect()
            .await;

        // Signer keys is already checked
        assert!(
            owned_chain_ids.len() == 0,
            "run `linera wallet request-chain` to create miner chain"
        );

        // We need to sync block, but we don't need to process message
        chain_listener_config.skip_process_inbox = true;

        let storage = context.storage().clone();

        // TODO: sync chain
        // TODO: check if chain is miner, if not, register
        // TODO: subscribe to block height and nonce

        Self {
            context: Arc::new(Mutex::new(context)),
            storage,

            meme_proxy_application_id,
            new_block_notifier: Arc::new(Notify::new()),
            chain_listener_config,
        }
    }

    pub fn meme_proxy_application_id(&self) -> ApplicationId {
        self.meme_proxy_application_id
    }

    async fn mine_task(&self, cancellation_token: CancellationToken) {
        loop {
            tokio::select! {
                _ = self.new_block_notifier.notified() => {
                    // TODO: get new chains
                    // TODO: assign new chains to owner
                    // TODO: if new block height or nonce got, stop previous mining and launch new one
                    // TODO: create Mine operation when hash got
                }
                _ = cancellation_token.cancelled() => {
                    tracing::info!("quit meme miner");
                    break;
                }
            }
        }
    }

    pub async fn run(&self, cancellation_token: CancellationToken) -> anyhow::Result<()> {
        let chain_listener = ChainListener::new(
            self.chain_listener_config.clone(),
            self.context.clone(),
            self.storage.clone(),
            cancellation_token.clone(),
            Arc::new(Mutex::new(tokio::sync::mpsc::unbounded_channel().1)),
        )
        .run(false)
        .await?;
        let mine_task = self.mine_task(cancellation_token);

        futures::select! {
            result = Box::pin(chain_listener).fuse() => result?,
            _ = Box::pin(mine_task).fuse() => {},
        };

        Ok(())
    }
}
