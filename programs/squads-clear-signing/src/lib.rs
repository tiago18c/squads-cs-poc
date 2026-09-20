//! # Squads Clear Signing
//!
//! Companion program for Squads Protocol v4 that makes proposal approvals
//! *clear-signable* on offline / air-gapped devices.
//!
//! ## The problem
//!
//! A Squads `proposal_approve` instruction only references a proposal PDA —
//! the actual transaction being approved lives in an on-chain
//! `VaultTransaction` account the offline signer cannot see. An offline device
//! that decodes instructions purely from IDL + instruction data therefore
//! cannot show the signer *what* they are approving ("blind signing").
//!
//! ## The fix
//!
//! The approving wallet prepends a `verify_proposal` instruction to the same
//! transaction as the Squads vote. Its arguments carry the *complete expected
//! content* of the vault transaction (every program id, account meta, and raw
//! instruction data blob) — all of it structured and decodable offline from
//! this program's IDL. On-chain, `verify_proposal`:
//!
//! 1. re-derives the `VaultTransaction`/`Proposal` PDAs from
//!    `(multisig, transaction_index)`, binding the vote to exactly one
//!    transaction;
//! 2. deserializes the stored `VaultTransaction` and diffs it byte-for-byte
//!    against the expected instructions (resolving address-lookup-table keys
//!    through the actual table accounts, in Squads' execution order);
//! 3. reads the instructions sysvar and requires the whole outer transaction
//!    to consist only of this program, compute-budget instructions, and the
//!    expected Squads vote for exactly this proposal / member / action.
//!
//! Any mismatch aborts the transaction, so the vote never lands. If the
//! transaction succeeds, the only thing that happened is the vote the signer
//! actually saw.

use anchor_lang::prelude::*;
use solana_instructions_sysvar as sysvar_instructions;

pub mod errors;
pub mod squads;
pub mod validation;

use errors::ClearSigningError;
use validation::{AccountKeys, VoteExpectation};

declare_id!("7xs3LhQjKoCGfXm2qst7LUhismrG1bGxz5Jw6AHij7eu");

#[program]
pub mod squads_clear_signing {
    use super::*;

    /// Verify that the Squads v4 vault transaction stored on-chain matches
    /// `args.instructions` exactly, and that this transaction contains the
    /// matching Squads vote instruction (and nothing else). Aborts otherwise.
    pub fn verify_proposal(ctx: Context<VerifyProposal>, args: VerifyProposalArgs) -> Result<()> {
        // 1. The transaction account must be the canonical PDA for
        //    (multisig, transaction_index) and owned by Squads v4.
        let transaction_pda = squads::derive_transaction_pda(&args.multisig, args.transaction_index);
        require_keys_eq!(
            ctx.accounts.transaction.key(),
            transaction_pda,
            ClearSigningError::TransactionPdaMismatch
        );
        require_keys_eq!(
            *ctx.accounts.transaction.owner,
            squads::SQUADS_PROGRAM_ID,
            ClearSigningError::InvalidTransactionOwner
        );

        // The proposal PDA shares the same seeds plus a suffix, so deriving it
        // from the same inputs binds proposal <-> transaction <-> multisig.
        let proposal_pda = squads::derive_proposal_pda(&args.multisig, args.transaction_index);

        // 2. Decode the stored vault transaction. The discriminator check also
        //    guarantees this is a VaultTransaction, not a ConfigTransaction or
        //    Batch living at the same seed schema.
        let vault_tx = {
            let data = ctx.accounts.transaction.try_borrow_data()?;
            squads::VaultTransaction::deserialize_checked(&data)?
        };
        require_keys_eq!(vault_tx.multisig, args.multisig, ClearSigningError::MultisigMismatch);
        require_eq!(
            vault_tx.index,
            args.transaction_index,
            ClearSigningError::TransactionIndexMismatch
        );
        require_eq!(
            vault_tx.vault_index,
            args.vault_index,
            ClearSigningError::VaultIndexMismatch
        );
        require_eq!(
            vault_tx.ephemeral_signer_bumps.len(),
            usize::from(args.num_ephemeral_signers),
            ClearSigningError::EphemeralSignersMismatch
        );

        // 3. Resolve the full account key table. Any address lookup tables the
        //    message references must be passed as remaining accounts, in order.
        let lookups = &vault_tx.message.address_table_lookups;
        require!(
            ctx.remaining_accounts.len() == lookups.len(),
            ClearSigningError::LookupTableCountMismatch
        );
        let mut tables: Vec<Vec<Pubkey>> = Vec::with_capacity(lookups.len());
        for (account, lookup) in ctx.remaining_accounts.iter().zip(lookups.iter()) {
            require_keys_eq!(
                account.key(),
                lookup.account_key,
                ClearSigningError::LookupTableAddressMismatch
            );
            require_keys_eq!(
                *account.owner,
                validation::ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
                ClearSigningError::InvalidLookupTableOwner
            );
            let data = account.try_borrow_data()?;
            tables.push(validation::parse_lookup_table_addresses(&data)?);
        }
        let keys = AccountKeys::resolve(&vault_tx.message, &tables)?;

        // 4. Diff the stored message against what the offline signer saw.
        validation::validate_instructions(&vault_tx.message, &keys, &args.instructions)?;

        // 5. Enforce the shape of this (outer) transaction via the sysvar:
        //    nothing but us, compute budget, and the expected vote.
        let sysvar_info = ctx.accounts.instructions_sysvar.to_account_info();
        let num_instructions = {
            let data = sysvar_info.try_borrow_data()?;
            require!(data.len() >= 2, ClearSigningError::InstructionsSysvarError);
            usize::from(u16::from_le_bytes([data[0], data[1]]))
        };
        let mut top_level = Vec::with_capacity(num_instructions);
        for i in 0..num_instructions {
            let ix = sysvar_instructions::load_instruction_at_checked(i, &sysvar_info)
                .map_err(|_| error!(ClearSigningError::InstructionsSysvarError))?;
            top_level.push(ix);
        }
        validation::validate_transaction_shape(
            &top_level,
            &VoteExpectation {
                self_program: crate::ID,
                multisig: args.multisig,
                proposal: proposal_pda,
                member: args.member,
                action: args.action,
            },
        )?;

        msg!(
            "clear-signing OK: {:?} on proposal {} (multisig {}, tx index {}, {} instructions) by member {}",
            args.action,
            proposal_pda,
            args.multisig,
            args.transaction_index,
            vault_tx.message.instructions.len(),
            args.member,
        );
        Ok(())
    }

    /// Verify that a BPF upgradeable-loader Buffer account's program bytes
    /// hash to `args.expected_hash` (SHA-256 via the native `sol_sha256`
    /// syscall over the bytes with trailing zeros trimmed — byte-identical to
    /// `solana-verify get-buffer-hash`).
    /// Bundle it before `verify_proposal` + the Squads vote when the proposal
    /// under approval is a program upgrade, so the offline signer sees the
    /// exact build being deployed, not just the buffer's address. Aborts the
    /// transaction on any mismatch.
    pub fn verify_buffer_hash(
        ctx: Context<VerifyBufferHash>,
        args: VerifyBufferHashArgs,
    ) -> Result<()> {
        let buffer = &ctx.accounts.buffer;
        require_keys_eq!(
            buffer.key(),
            args.buffer,
            ClearSigningError::BufferKeyMismatch
        );
        require_keys_eq!(
            *buffer.owner,
            validation::BPF_LOADER_UPGRADEABLE_ID,
            ClearSigningError::InvalidBufferOwner
        );
        let data = buffer.try_borrow_data()?;
        let program_bytes = validation::extract_buffer_program_bytes(&data)?;
        let hash = validation::compute_program_hash(program_bytes);
        // `expected_hash` is a lowercase hex string (64 chars) so an offline
        // device renders the human-readable digest — the exact value a reviewer
        // compares against `solana-verify get-buffer-hash`.
        let expected = validation::hex_to_hash(&args.expected_hash)?;
        if hash != expected {
            msg!("buffer {} hash mismatch", buffer.key());
            msg!("  computed: {}", validation::hash_to_hex(&hash));
            msg!("  expected: {}", args.expected_hash);
            return err!(ClearSigningError::BufferHashMismatch);
        }
        msg!(
            "buffer hash OK: {} ({} program bytes, trailing zeros trimmed)",
            buffer.key(),
            validation::trim_trailing_zeros(program_bytes).len(),
        );
        Ok(())
    }
}

#[derive(Accounts)]
pub struct VerifyProposal<'info> {
    /// The Squads v4 `VaultTransaction` account under vote.
    /// CHECK: owner, PDA derivation, and discriminator are all validated in
    /// the handler against the `(multisig, transaction_index)` in the args.
    pub transaction: UncheckedAccount<'info>,

    /// CHECK: constrained to the instructions sysvar address.
    #[account(address = sysvar_instructions::ID @ ClearSigningError::InstructionsSysvarError)]
    pub instructions_sysvar: UncheckedAccount<'info>,
    //
    // remaining_accounts: the address lookup table accounts referenced by the
    // vault transaction message, in message order (usually none).
}

#[derive(Accounts)]
pub struct VerifyBufferHash<'info> {
    /// The BPF upgradeable-loader Buffer account whose contents are checked.
    /// CHECK: owner, state tag, and content hash are validated in the handler.
    pub buffer: UncheckedAccount<'info>,
}

/// Binds a buffer account to the exact build the offline signer reviewed.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct VerifyBufferHashArgs {
    /// The buffer account under verification (must equal the passed account —
    /// duplicated here so the offline device renders it from the args alone).
    pub buffer: Pubkey,
    /// SHA-256 of the buffer's program bytes with trailing zeros trimmed, as a
    /// **lowercase hex string** (64 chars) — byte-identical to what
    /// `solana-verify get-buffer-hash` prints, shown as-is to the signer so it
    /// can be compared against a locally reproduced build.
    pub expected_hash: String,
}

/// Everything the offline signer needs to see, in one IDL-decodable blob.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct VerifyProposalArgs {
    /// The Squads v4 multisig this proposal belongs to.
    pub multisig: Pubkey,
    /// Index of the vault transaction / proposal being voted on.
    pub transaction_index: u64,
    /// Vault (authority) index the transaction executes under.
    pub vault_index: u8,
    /// Number of ephemeral signer PDAs the transaction uses (usually 0).
    pub num_ephemeral_signers: u8,
    /// The multisig member casting the vote — must be the signer of the
    /// sibling Squads vote instruction (i.e. the offline device's own key).
    pub member: Pubkey,
    /// Which vote the sibling Squads instruction must be.
    pub action: ProposalAction,
    /// The complete, expanded instruction list of the vault transaction.
    /// Must match the on-chain `VaultTransaction` exactly.
    pub instructions: Vec<ExpectedInstruction>,
}

/// The kind of Squads v4 vote instruction expected next to `verify_proposal`.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalAction {
    /// `proposal_approve`
    Approve,
    /// `proposal_reject`
    Reject,
    /// `proposal_cancel`
    Cancel,
    /// `proposal_cancel_v2`
    CancelV2,
}

impl ProposalAction {
    pub fn discriminator(&self) -> [u8; 8] {
        match self {
            ProposalAction::Approve => squads::IX_PROPOSAL_APPROVE,
            ProposalAction::Reject => squads::IX_PROPOSAL_REJECT,
            ProposalAction::Cancel => squads::IX_PROPOSAL_CANCEL,
            ProposalAction::CancelV2 => squads::IX_PROPOSAL_CANCEL_V2,
        }
    }
}

/// One expected instruction inside the vault transaction, fully expanded
/// (indexes resolved to pubkeys) so an offline device can render it.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct ExpectedInstruction {
    /// Program the instruction invokes.
    pub program_id: Pubkey,
    /// Ordered account metas, exactly as compiled into the vault transaction.
    pub accounts: Vec<ExpectedAccountMeta>,
    /// Raw instruction data, byte-for-byte.
    pub data: Vec<u8>,
}

/// Expected account meta of an inner instruction.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct ExpectedAccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}
