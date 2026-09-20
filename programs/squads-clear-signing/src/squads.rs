//! Minimal read-only mirror of the Squads Protocol v4 account layouts.
//!
//! Layouts verified against `Squads-Protocol/v4` `programs/squads_multisig_program`
//! (`state/vault_transaction.rs`, `state/proposal.rs`, `state/seeds.rs`,
//! `instructions/proposal_vote.rs`, `utils/executable_transaction_message.rs`).
//! We deliberately do not depend on the `squads-multisig-program` crate to keep
//! the dependency surface of this security-critical program minimal.

use anchor_lang::prelude::*;

use crate::errors::ClearSigningError;

/// Squads Protocol v4 program id (mainnet & devnet deployment).
pub const SQUADS_PROGRAM_ID: Pubkey = pubkey!("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf");

// PDA seeds (state/seeds.rs).
pub const SEED_PREFIX: &[u8] = b"multisig";
pub const SEED_TRANSACTION: &[u8] = b"transaction";
pub const SEED_PROPOSAL: &[u8] = b"proposal";

/// Anchor account discriminator: sha256("account:VaultTransaction")[..8].
pub const VAULT_TRANSACTION_DISCRIMINATOR: [u8; 8] = [168, 250, 162, 100, 81, 14, 162, 207];

/// Anchor instruction discriminators for the proposal vote instructions:
/// sha256("global:<name>")[..8].
pub const IX_PROPOSAL_APPROVE: [u8; 8] = [144, 37, 164, 136, 188, 216, 42, 248];
pub const IX_PROPOSAL_REJECT: [u8; 8] = [243, 62, 134, 156, 230, 106, 246, 135];
pub const IX_PROPOSAL_CANCEL: [u8; 8] = [27, 42, 127, 237, 38, 163, 84, 203];
pub const IX_PROPOSAL_CANCEL_V2: [u8; 8] = [205, 41, 194, 61, 220, 139, 16, 247];

/// Derive the `VaultTransaction` PDA for a given multisig and transaction index.
pub fn derive_transaction_pda(multisig: &Pubkey, transaction_index: u64) -> Pubkey {
    Pubkey::find_program_address(
        &[
            SEED_PREFIX,
            multisig.as_ref(),
            SEED_TRANSACTION,
            &transaction_index.to_le_bytes(),
        ],
        &SQUADS_PROGRAM_ID,
    )
    .0
}

/// Derive the `Proposal` PDA for a given multisig and transaction index.
pub fn derive_proposal_pda(multisig: &Pubkey, transaction_index: u64) -> Pubkey {
    Pubkey::find_program_address(
        &[
            SEED_PREFIX,
            multisig.as_ref(),
            SEED_TRANSACTION,
            &transaction_index.to_le_bytes(),
            SEED_PROPOSAL,
        ],
        &SQUADS_PROGRAM_ID,
    )
    .0
}

/// Mirror of `squads_multisig_program::state::VaultTransaction`.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct VaultTransaction {
    pub multisig: Pubkey,
    pub creator: Pubkey,
    pub index: u64,
    pub bump: u8,
    pub vault_index: u8,
    pub vault_bump: u8,
    pub ephemeral_signer_bumps: Vec<u8>,
    pub message: VaultTransactionMessage,
}

impl VaultTransaction {
    /// Deserialize from raw account data, checking the Anchor discriminator.
    /// Tolerates trailing bytes after the borsh payload.
    pub fn deserialize_checked(data: &[u8]) -> Result<Self> {
        require!(
            data.len() > 8 && data[..8] == VAULT_TRANSACTION_DISCRIMINATOR,
            ClearSigningError::NotAVaultTransaction
        );
        let mut rest = &data[8..];
        AnchorDeserialize::deserialize(&mut rest)
            .map_err(|_| error!(ClearSigningError::TransactionDeserializationError))
    }
}

/// Mirror of `squads_multisig_program::state::VaultTransactionMessage`.
///
/// Accounts are ordered exactly like a sanitized Solana message:
/// `[writable signers][readonly signers][writable non-signers][readonly non-signers]`,
/// followed (in the combined index space used by `instructions`) by keys loaded
/// from address lookup tables: all writable lookups first, then all readonly ones.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct VaultTransactionMessage {
    pub num_signers: u8,
    pub num_writable_signers: u8,
    pub num_writable_non_signers: u8,
    pub account_keys: Vec<Pubkey>,
    pub instructions: Vec<MultisigCompiledInstruction>,
    pub address_table_lookups: Vec<MultisigMessageAddressTableLookup>,
}

impl VaultTransactionMessage {
    /// Is the given index (into the combined key space) a required signer?
    /// Mirrors `VaultTransactionMessage::is_signer_index`.
    pub fn is_signer_index(&self, index: usize) -> bool {
        index < usize::from(self.num_signers)
    }

    /// Is the given *static* key index writable?
    /// Mirrors `VaultTransactionMessage::is_static_writable_index`.
    pub fn is_static_writable_index(&self, key_index: usize) -> bool {
        let num_account_keys = self.account_keys.len();
        let num_signers = usize::from(self.num_signers);
        let num_writable_signers = usize::from(self.num_writable_signers);
        let num_writable_non_signers = usize::from(self.num_writable_non_signers);

        if key_index >= num_account_keys {
            return false;
        }
        if key_index < num_writable_signers {
            return true;
        }
        if key_index >= num_signers {
            let index_into_non_signers = key_index.saturating_sub(num_signers);
            return index_into_non_signers < num_writable_non_signers;
        }
        false
    }
}

/// Mirror of `squads_multisig_program::state::MultisigCompiledInstruction`.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct MultisigCompiledInstruction {
    pub program_id_index: u8,
    pub account_indexes: Vec<u8>,
    pub data: Vec<u8>,
}

/// Mirror of `squads_multisig_program::state::MultisigMessageAddressTableLookup`.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct MultisigMessageAddressTableLookup {
    pub account_key: Pubkey,
    pub writable_indexes: Vec<u8>,
    pub readonly_indexes: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_transaction_round_trip() {
        let tx = VaultTransaction {
            multisig: Pubkey::new_unique(),
            creator: Pubkey::new_unique(),
            index: 42,
            bump: 254,
            vault_index: 0,
            vault_bump: 253,
            ephemeral_signer_bumps: vec![255],
            message: VaultTransactionMessage {
                num_signers: 2,
                num_writable_signers: 1,
                num_writable_non_signers: 1,
                account_keys: vec![Pubkey::new_unique(), Pubkey::new_unique()],
                instructions: vec![MultisigCompiledInstruction {
                    program_id_index: 1,
                    account_indexes: vec![0],
                    data: vec![1, 2, 3],
                }],
                address_table_lookups: vec![],
            },
        };

        let mut data = VAULT_TRANSACTION_DISCRIMINATOR.to_vec();
        tx.serialize(&mut data).unwrap();
        // Anchor accounts may carry trailing padding; make sure we tolerate it.
        data.extend_from_slice(&[0u8; 7]);

        let decoded = VaultTransaction::deserialize_checked(&data).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn rejects_wrong_discriminator() {
        // A Proposal discriminator followed by garbage must be rejected.
        let mut data = vec![26, 94, 189, 187, 116, 136, 53, 33];
        data.extend_from_slice(&[0u8; 128]);
        assert!(VaultTransaction::deserialize_checked(&data).is_err());
    }

    #[test]
    fn static_writable_semantics() {
        // Layout: [ws, ws, rs, wn, rn] -> num_signers=3, num_writable_signers=2,
        // num_writable_non_signers=1, 5 static keys.
        let message = VaultTransactionMessage {
            num_signers: 3,
            num_writable_signers: 2,
            num_writable_non_signers: 1,
            account_keys: (0..5).map(|_| Pubkey::new_unique()).collect(),
            instructions: vec![],
            address_table_lookups: vec![],
        };
        let writable: Vec<bool> = (0..5).map(|i| message.is_static_writable_index(i)).collect();
        assert_eq!(writable, vec![true, true, false, true, false]);
        let signer: Vec<bool> = (0..5).map(|i| message.is_signer_index(i)).collect();
        assert_eq!(signer, vec![true, true, true, false, false]);
        // Out of bounds is never writable.
        assert!(!message.is_static_writable_index(5));
    }
}
