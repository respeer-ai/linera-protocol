use std::sync::Arc;

use linera_base::identifiers::ApplicationId;
use linera_client::chain_listener::ClientContext;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
pub struct MemeMiner<C>
where
    C: ClientContext,
{
    context: C,

    meme_proxy_application_id: ApplicationId,
    new_block_notifier: Arc<Notify>,
}

impl<C> MemeMiner<C>
where
    C: ClientContext + 'static,
{
    pub fn new(meme_proxy_application_id: ApplicationId, context: C) -> Self {
        // TODO: check chain and owner in wallet, if chain is not available, request chain
        // TODO: sync chain
        // TODO: check if chain is miner, if not, register
        // TODO: subscribe to block height and nonce
        Self {
            meme_proxy_application_id,
            context,
            new_block_notifier: Arc::new(Notify::new()),
        }
    }

    pub fn meme_proxy_application_id(&self) -> ApplicationId {
        self.meme_proxy_application_id
    }

    pub async fn run(&mut self, cancellation_token: CancellationToken) {
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
}
