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
//! 1. binds the vote to exactly one transaction: the vote's `Proposal` and the
//!    `VaultTransaction` must both be Squads-owned, carry the right
//!    discriminators, and record the same `(multisig, transaction_index)`;
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
        // 1. The proposal under vote. Squads only creates a `Proposal` at the
        //    PDA `(multisig, transaction_index)` and records those two values in
        //    it, so a Squads-owned account with the Proposal discriminator tells
        //    us authoritatively which transaction it belongs to — no PDA
        //    derivation needed. Step 5 requires the sibling vote to target
        //    exactly this account.
        let proposal_key = ctx.accounts.proposal.key();
        require_keys_eq!(
            *ctx.accounts.proposal.owner,
            squads::SQUADS_PROGRAM_ID,
            ClearSigningError::InvalidProposalOwner
        );
        let proposal = {
            let data = ctx.accounts.proposal.try_borrow_data()?;
            squads::ProposalHeader::parse_checked(&data)?
        };
        require_keys_eq!(
            proposal.multisig,
            args.multisig,
            ClearSigningError::ProposalMultisigMismatch
        );
        require_eq!(
            proposal.transaction_index,
            args.transaction_index,
            ClearSigningError::ProposalIndexMismatch
        );

        // 2. The vault transaction. Same argument: Squads only creates it at the
        //    PDA `(multisig, index)`, so ownership + discriminator + matching
        //    stored `(multisig, index)` identify the proposal's transaction.
        //    The discriminator check also guarantees this is a VaultTransaction,
        //    not a ConfigTransaction or Batch sharing the index.
        require_keys_eq!(
            *ctx.accounts.transaction.owner,
            squads::SQUADS_PROGRAM_ID,
            ClearSigningError::InvalidTransactionOwner
        );
        let vault_tx = {
            let data = ctx.accounts.transaction.try_borrow_data()?;
            squads::VaultTransaction::deserialize_checked(&data)?
        };
        require_keys_eq!(vault_tx.multisig, proposal.multisig, ClearSigningError::MultisigMismatch);
        require_eq!(
            vault_tx.index,
            proposal.transaction_index,
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
                proposal: proposal_key,
                member: args.member,
                action: args.action,
            },
        )?;

        msg!(
            "clear-signing OK: {:?} on proposal {} (multisig {}, tx index {}, {} instructions) by member {}",
            args.action,
            proposal_key,
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
        let (hash, trimmed_len) = validation::compute_program_hash(program_bytes);
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
            trimmed_len,
        );
        Ok(())
    }

    /// Assert that an arbitrary account's raw data hashes to
    /// `args.expected_hash` (SHA-256 over the **untrimmed** account data, as
    /// lowercase hex), and — when `args.owner` is `Some` — that the account is
    /// owned by that program. Lets an offline signer pin the exact state of
    /// any account a proposal depends on (a config, a mint, an oracle, ...)
    /// **at vote time**. Only data and (optionally) owner are covered — not
    /// lamports or the executable flag; a non-existent account has empty data
    /// and the system program as owner. Aborts the transaction on any mismatch.
    pub fn assert_account_hash(
        ctx: Context<AssertAccountHash>,
        args: AssertAccountHashArgs,
    ) -> Result<()> {
        let account = &ctx.accounts.account;
        require_keys_eq!(
            account.key(),
            args.account,
            ClearSigningError::AssertedAccountMismatch
        );
        if let Some(owner) = args.owner {
            require_keys_eq!(*account.owner, owner, ClearSigningError::AccountOwnerMismatch);
        }
        let data = account.try_borrow_data()?;
        let hash = validation::compute_account_hash(&data);
        validation::check_hash(
            "account",
            &hash,
            &args.expected_hash,
            ClearSigningError::AccountHashMismatch,
        )?;
        msg!(
            "account hash OK: {} (owner {}, {} bytes)",
            account.key(),
            account.owner,
            data.len(),
        );
        Ok(())
    }

    /// Assert that a deployed loader-v3 program runs exactly the build hashing
    /// to `args.expected_hash`. A specialization of `assert_account_hash` for
    /// upgradeable programs, which keep their code in a separate ProgramData
    /// account:
    ///
    /// 1. the `program` account equals `args.program`, is owned by the BPF
    ///    upgradeable loader, and is in the `Program` state;
    /// 2. the `programdata_address` stored in it equals the passed
    ///    `program_data` account, which is also loader-owned and in the
    ///    `ProgramData` state;
    /// 3. the ProgramData's program bytes (trailing zeros trimmed) SHA-256 to
    ///    `args.expected_hash` — byte-identical to
    ///    `solana-verify get-program-hash <program>`.
    ///
    /// The ProgramData metadata (deploy slot, upgrade authority) is not part
    /// of the hash, so the digest identifies the build, not the deployment.
    /// Like every assertion here it holds at vote time only: a program with
    /// a live upgrade authority can change before the proposal executes.
    pub fn assert_program_revision(
        ctx: Context<AssertProgramRevision>,
        args: AssertProgramRevisionArgs,
    ) -> Result<()> {
        let program = &ctx.accounts.program;
        let program_data = &ctx.accounts.program_data;

        // 1. The program account itself.
        require_keys_eq!(program.key(), args.program, ClearSigningError::ProgramKeyMismatch);
        require_keys_eq!(
            *program.owner,
            validation::BPF_LOADER_UPGRADEABLE_ID,
            ClearSigningError::InvalidProgramOwner
        );
        let programdata_address = {
            let data = program.try_borrow_data()?;
            validation::parse_program_account(&data)?
        };

        // 2. Its contents must point at the passed ProgramData account.
        require_keys_eq!(
            program_data.key(),
            programdata_address,
            ClearSigningError::ProgramDataAddressMismatch
        );
        require_keys_eq!(
            *program_data.owner,
            validation::BPF_LOADER_UPGRADEABLE_ID,
            ClearSigningError::InvalidProgramDataOwner
        );

        // 3. The ProgramData's program bytes hash.
        let data = program_data.try_borrow_data()?;
        let program_bytes = validation::extract_programdata_program_bytes(&data)?;
        let (hash, trimmed_len) = validation::compute_program_hash(program_bytes);
        validation::check_hash(
            "program",
            &hash,
            &args.expected_hash,
            ClearSigningError::ProgramHashMismatch,
        )?;
        msg!(
            "program revision OK: {} (programdata {}, {} program bytes, trailing zeros trimmed)",
            program.key(),
            program_data.key(),
            trimmed_len,
        );
        Ok(())
    }
}

#[derive(Accounts)]
pub struct VerifyProposal<'info> {
    /// The Squads v4 `Proposal` being voted on (the sibling vote's proposal).
    /// CHECK: owner, discriminator, and `(multisig, transaction_index)` are
    /// validated in the handler; the vote must target this exact account.
    pub proposal: UncheckedAccount<'info>,

    /// The Squads v4 `VaultTransaction` the proposal belongs to.
    /// CHECK: owner, discriminator, and `(multisig, index)` are validated in
    /// the handler against the proposal.
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

#[derive(Accounts)]
pub struct AssertAccountHash<'info> {
    /// The account whose data (and optionally owner) is asserted.
    /// CHECK: key, optional owner, and content hash are validated in the handler.
    pub account: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct AssertProgramRevision<'info> {
    /// The loader-v3 Program account (the program id).
    /// CHECK: key, owner, and `Program` state are validated in the handler.
    pub program: UncheckedAccount<'info>,
    /// The ProgramData account the program account points at.
    /// CHECK: must equal the program's stored `programdata_address`; owner,
    /// `ProgramData` state, and program-bytes hash are validated in the handler.
    pub program_data: UncheckedAccount<'info>,
}

/// Binds an arbitrary account to the exact state the offline signer reviewed.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct AssertAccountHashArgs {
    /// The account under verification (must equal the passed account —
    /// duplicated here so the offline device renders it from the args alone).
    pub account: Pubkey,
    /// If set, the program that must own the account.
    pub owner: Option<Pubkey>,
    /// SHA-256 of the account's raw data (no trimming), as a **lowercase hex
    /// string** (64 chars).
    pub expected_hash: String,
}

/// Binds a deployed upgradeable program to the exact build the offline
/// signer reviewed.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct AssertProgramRevisionArgs {
    /// The program id under verification (must equal the passed account).
    pub program: Pubkey,
    /// SHA-256 of the ProgramData's program bytes with trailing zeros
    /// trimmed, as a **lowercase hex string** (64 chars) — byte-identical to
    /// `solana-verify get-program-hash <program>`.
    pub expected_hash: String,
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
