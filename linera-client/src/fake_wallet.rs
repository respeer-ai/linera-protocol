use std::str::FromStr;

use linera_base::{
    crypto::{KeyPair, PublicKey},
    data_types::Timestamp,
    identifiers::ChainId,
};
use linera_core::{client::ChainClient, node::LocalValidatorNodeProvider};
use linera_storage::Storage;
use serde::{Deserialize, Serialize};

use crate::{wallet::UserChain, Error};

#[cfg(feature = "no-storage")]
#[derive(Serialize, Deserialize)]
pub struct FakeWallet {}

#[cfg(feature = "no-storage")]
impl Extend<UserChain> for FakeWallet {
    fn extend<Chains: IntoIterator<Item = UserChain>>(&mut self, _chains: Chains) {}
}

#[cfg(feature = "no-storage")]
impl FakeWallet {
    pub fn new() -> Self {
        FakeWallet {}
    }

    pub fn chain_ids(&self) -> Vec<ChainId> {
        Vec::new()
    }

    pub fn key_pair_for_pk(&self, _key: &PublicKey) -> Option<KeyPair> {
        None
    }

    pub fn default_chain(&self) -> Option<ChainId> {
        None
    }

    pub fn get(&self, _chain_id: ChainId) -> Option<&UserChain> {
        None
    }

    pub fn genesis_admin_chain(&self) -> ChainId {
        ChainId::from_str("").unwrap()
    }

    pub fn insert(&mut self, _chain: UserChain) {}

    pub async fn update_from_state<P, S>(&mut self, _chain_client: &ChainClient<P, S>)
    where
        P: LocalValidatorNodeProvider + Sync + 'static,
        S: Storage + Clone + Send + Sync + 'static,
    {
    }

    pub fn assign_new_chain_to_public_key(
        &mut self,
        _key: PublicKey,
        _chain_id: ChainId,
        _timestamp: Timestamp,
    ) -> Result<(), Error> {
        Ok(())
    }

    pub fn set_default_chain(&mut self, _chain_id: ChainId) -> Result<(), Error> {
        Ok(())
    }

    pub fn set_default_chain_with_public_key(
        &mut self,
        _public_key: PublicKey,
        _chain_id: ChainId,
    ) -> Result<(), Error> {
        Ok(())
    }
}
