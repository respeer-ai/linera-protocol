use async_graphql::{InputObject, SimpleObject};
use linera_base::{
    crypto::CryptoHash,
    data_types::{BlockHeight, Epoch, Round, Timestamp},
    identifiers::{AccountOwner, ChainId},
};
use serde::{Deserialize, Serialize};
use serde_alias::serde_alias;

use crate::data_types::{BlockExecutionOutcome, ProposalContent, ProposedBlock, Transaction};

#[serde_alias(CamelCase, SnakeCase, PascalCase)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "InputWrapperProposedBlock")]
pub struct WrapperProposedBlock {
    /// The chain to which this block belongs.
    pub chain_id: ChainId,
    /// The number identifying the current configuration.
    pub epoch: Epoch,
    /// The transactions to execute in this block. Each transaction can be either
    /// incoming messages or an operation.
    pub transactions: Vec<Transaction>,
    /// The block height.
    pub height: BlockHeight,
    /// The timestamp when this block was created. This must be later than all messages received
    /// in this block, but no later than the current time.
    pub timestamp: Timestamp,
    /// The user signing for the operations in the block and paying for their execution
    /// fees. If set, this must be the `owner` in the block proposal. `None` means that
    /// the default account of the chain is used. This value is also used as recipient of
    /// potential refunds for the message grants created by the operations.
    pub authenticated_signer: Option<AccountOwner>,
    /// Certified hash (see `Certificate` below) of the previous block in the
    /// chain, if any.
    pub previous_block_hash: Option<CryptoHash>,
}

impl From<ProposedBlock> for WrapperProposedBlock {
    fn from(block: ProposedBlock) -> Self {
        let ProposedBlock {
            chain_id,
            epoch,
            transactions,
            height,
            timestamp,
            authenticated_signer,
            previous_block_hash,
        } = block;

        WrapperProposedBlock {
            chain_id,
            epoch,
            transactions,
            height,
            timestamp,
            authenticated_signer,
            previous_block_hash,
        }
    }
}

impl Into<ProposedBlock> for WrapperProposedBlock {
    fn into(self) -> ProposedBlock {
        let WrapperProposedBlock {
            chain_id,
            epoch,
            transactions,
            height,
            timestamp,
            authenticated_signer,
            previous_block_hash,
        } = self;

        ProposedBlock {
            chain_id,
            epoch,
            transactions,
            height,
            timestamp,
            authenticated_signer,
            previous_block_hash,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "InputWrapperProposalContent")]
pub struct WrapperProposalContent {
    /// The proposed block.
    pub block: WrapperProposedBlock,
    /// The consensus round in which this proposal is made.
    pub round: Round,
    /// If this is a retry from an earlier round, the execution outcome.
    pub outcome: Option<BlockExecutionOutcome>,
}

impl From<ProposalContent> for WrapperProposalContent {
    fn from(content: ProposalContent) -> Self {
        let ProposalContent {
            block,
            round,
            outcome,
        } = content;

        WrapperProposalContent {
            block: WrapperProposedBlock::from(block),
            round,
            outcome,
        }
    }
}

impl Into<ProposalContent> for WrapperProposalContent {
    fn into(self) -> ProposalContent {
        let WrapperProposalContent {
            block,
            round,
            outcome,
        } = self;

        ProposalContent {
            block: block.into(),
            round,
            outcome,
        }
    }
}
