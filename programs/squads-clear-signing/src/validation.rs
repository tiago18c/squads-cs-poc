//! Pure validation logic: resolving the vault transaction's account key table
//! (including address lookup tables), diffing the stored message against the
//! expected instruction list, and enforcing the strict shape of the outer
//! (approval) transaction via the instructions sysvar.
//!
//! Everything here is a pure function over decoded data so it can be unit
//! tested without a Solana runtime.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::Instruction;

use crate::errors::ClearSigningError;
use crate::squads::{VaultTransactionMessage, SQUADS_PROGRAM_ID};
use crate::{ExpectedInstruction, ProposalAction};

/// The address lookup table program.
pub const ADDRESS_LOOKUP_TABLE_PROGRAM_ID: Pubkey =
    pubkey!("AddressLookupTab1e1111111111111111111111111");

/// The compute budget program — the only third-party program tolerated
/// alongside a clear-signed vote (wallets add CU limit/price instructions).
pub const COMPUTE_BUDGET_PROGRAM_ID: Pubkey =
    pubkey!("ComputeBudget111111111111111111111111111111");

/// The BPF upgradeable loader (loader-v3).
pub const BPF_LOADER_UPGRADEABLE_ID: Pubkey =
    pubkey!("BPFLoaderUpgradeab1e11111111111111111111111");

/// Serialized size of `UpgradeableLoaderState::Buffer` metadata: 4-byte enum
/// tag + `Option<Pubkey>` authority (1 + 32). Program bytes start here.
pub const BUFFER_METADATA_SIZE: usize = 37;

/// `UpgradeableLoaderState` bincode enum tag for the `Buffer` variant.
const BUFFER_STATE_TAG: u32 = 1;

/// `UpgradeableLoaderState` bincode enum tag for the `Program` variant.
const PROGRAM_STATE_TAG: u32 = 2;

/// `UpgradeableLoaderState` bincode enum tag for the `ProgramData` variant.
const PROGRAMDATA_STATE_TAG: u32 = 3;

/// Serialized size of `UpgradeableLoaderState::Program`: 4-byte enum tag +
/// 32-byte `programdata_address`.
const PROGRAM_ACCOUNT_SIZE: usize = 36;

/// Serialized size of `UpgradeableLoaderState::ProgramData` metadata: 4-byte
/// enum tag + 8-byte slot + `Option<Pubkey>` upgrade authority (1 + 32, always
/// reserved). Program bytes start here. Mirrors
/// `UpgradeableLoaderState::size_of_programdata_metadata()`.
pub const PROGRAMDATA_METADATA_SIZE: usize = 45;

/// Size of the serialized lookup-table meta (4-byte enum tag included);
/// addresses start at this offset. Mirrors
/// `solana_address_lookup_table_program::state::LOOKUP_TABLE_META_SIZE`.
pub const LOOKUP_TABLE_META_SIZE: usize = 56;

/// Parse the addresses stored in an address lookup table account.
pub fn parse_lookup_table_addresses(data: &[u8]) -> Result<Vec<Pubkey>> {
    require!(
        data.len() >= LOOKUP_TABLE_META_SIZE,
        ClearSigningError::InvalidLookupTableData
    );
    // ProgramState enum tag: 1 == LookupTable (0 == Uninitialized).
    let tag = u32::from_le_bytes(data[0..4].try_into().unwrap());
    require!(tag == 1, ClearSigningError::InvalidLookupTableData);
    let addresses = &data[LOOKUP_TABLE_META_SIZE..];
    require!(
        addresses.len() % 32 == 0,
        ClearSigningError::InvalidLookupTableData
    );
    Ok(addresses
        .chunks_exact(32)
        .map(|c| Pubkey::new_from_array(c.try_into().unwrap()))
        .collect())
}

/// The fully resolved account key table of a vault transaction, in the exact
/// index space used by `MultisigCompiledInstruction.account_indexes`:
/// `[static keys][loaded writable keys][loaded readonly keys]`.
///
/// Mirrors the resolution order of Squads'
/// `ExecutableTransactionMessage::get_account_by_index` / `is_writable_index`.
pub struct AccountKeys {
    keys: Vec<Pubkey>,
    num_static: usize,
    num_loaded_writable: usize,
    num_signers: usize,
    num_writable_signers: usize,
    num_writable_non_signers: usize,
}

impl AccountKeys {
    /// Build the combined key table from the message's static keys and the
    /// parsed addresses of each referenced lookup table (in message order).
    pub fn resolve(
        message: &VaultTransactionMessage,
        tables: &[Vec<Pubkey>],
    ) -> Result<Self> {
        require!(
            tables.len() == message.address_table_lookups.len(),
            ClearSigningError::LookupTableCountMismatch
        );

        let mut keys = message.account_keys.clone();
        let num_static = keys.len();

        // All writable lookups first (lookup order), then all readonly ones.
        for (lookup, table) in message.address_table_lookups.iter().zip(tables) {
            for &index in &lookup.writable_indexes {
                let key = table
                    .get(usize::from(index))
                    .ok_or(error!(ClearSigningError::LookupTableIndexOutOfBounds))?;
                keys.push(*key);
            }
        }
        let num_loaded_writable = keys.len() - num_static;
        for (lookup, table) in message.address_table_lookups.iter().zip(tables) {
            for &index in &lookup.readonly_indexes {
                let key = table
                    .get(usize::from(index))
                    .ok_or(error!(ClearSigningError::LookupTableIndexOutOfBounds))?;
                keys.push(*key);
            }
        }

        Ok(Self {
            keys,
            num_static,
            num_loaded_writable,
            num_signers: usize::from(message.num_signers),
            num_writable_signers: usize::from(message.num_writable_signers),
            num_writable_non_signers: usize::from(message.num_writable_non_signers),
        })
    }

    pub fn get(&self, index: usize) -> Result<&Pubkey> {
        self.keys
            .get(index)
            .ok_or(error!(ClearSigningError::AccountIndexOutOfBounds))
    }

    /// Only static keys can be required signers.
    pub fn is_signer(&self, index: usize) -> bool {
        index < self.num_signers
    }

    /// Mirrors Squads' `ExecutableTransactionMessage::is_writable_index`.
    pub fn is_writable(&self, index: usize) -> bool {
        if index < self.num_static {
            if index < self.num_writable_signers {
                return true;
            }
            if index >= self.num_signers {
                return index - self.num_signers < self.num_writable_non_signers;
            }
            return false;
        }
        index - self.num_static < self.num_loaded_writable
    }
}

/// Diff the stored, compiled vault transaction message against the expected
/// (fully expanded) instruction list the offline signer was shown.
pub fn validate_instructions(
    message: &VaultTransactionMessage,
    keys: &AccountKeys,
    expected: &[ExpectedInstruction],
) -> Result<()> {
    if message.instructions.len() != expected.len() {
        msg!(
            "instruction count mismatch: stored {}, expected {}",
            message.instructions.len(),
            expected.len()
        );
        return err!(ClearSigningError::InstructionCountMismatch);
    }

    for (i, (stored, exp)) in message.instructions.iter().zip(expected).enumerate() {
        let program_id = keys.get(usize::from(stored.program_id_index))?;
        if *program_id != exp.program_id {
            msg!("ix {}: program id {} != expected {}", i, program_id, exp.program_id);
            return err!(ClearSigningError::ProgramIdMismatch);
        }

        if stored.account_indexes.len() != exp.accounts.len() {
            msg!(
                "ix {}: account count {} != expected {}",
                i,
                stored.account_indexes.len(),
                exp.accounts.len()
            );
            return err!(ClearSigningError::AccountCountMismatch);
        }

        for (j, (&index, exp_meta)) in
            stored.account_indexes.iter().zip(&exp.accounts).enumerate()
        {
            let index = usize::from(index);
            let key = keys.get(index)?;
            if *key != exp_meta.pubkey {
                msg!("ix {} account {}: {} != expected {}", i, j, key, exp_meta.pubkey);
                return err!(ClearSigningError::AccountKeyMismatch);
            }
            if keys.is_writable(index) != exp_meta.is_writable {
                msg!(
                    "ix {} account {}: writable is {}, expected {}",
                    i,
                    j,
                    keys.is_writable(index),
                    exp_meta.is_writable
                );
                return err!(ClearSigningError::AccountWritableMismatch);
            }
            if keys.is_signer(index) != exp_meta.is_signer {
                msg!(
                    "ix {} account {}: signer is {}, expected {}",
                    i,
                    j,
                    keys.is_signer(index),
                    exp_meta.is_signer
                );
                return err!(ClearSigningError::AccountSignerMismatch);
            }
        }

        if stored.data != exp.data {
            msg!(
                "ix {}: data mismatch (stored {} bytes, expected {} bytes)",
                i,
                stored.data.len(),
                exp.data.len()
            );
            return err!(ClearSigningError::DataMismatch);
        }
    }

    Ok(())
}

/// Chunk size for the zero-tail scan in `trim_trailing_zeros`.
const ZERO_CHUNK: usize = 4096;
static ZEROS: [u8; ZERO_CHUNK] = [0; ZERO_CHUNK];

/// Returns `bytes` with every contiguous `0x00` byte at the end removed —
/// the normalization `solana-verify` applies before hashing program bytes
/// (deploy-time zero padding must not change the hash).
///
/// ProgramData accounts are often over-allocated by hundreds of KB to MBs, so
/// a byte-wise scan (~6 CU/byte in SBF) would exhaust the compute budget on
/// real programs. Whole zero chunks are skipped with the `sol_memcmp` syscall
/// (~ZERO_CHUNK/250 CU each); only the final partial chunk is scanned
/// byte-wise.
pub fn trim_trailing_zeros(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len();
    while end >= ZERO_CHUNK && is_zero_chunk(&bytes[end - ZERO_CHUNK..end]) {
        end -= ZERO_CHUNK;
    }
    let end = bytes[..end]
        .iter()
        .rposition(|&b| b != 0)
        .map(|i| i + 1)
        .unwrap_or(0);
    &bytes[..end]
}

fn is_zero_chunk(chunk: &[u8]) -> bool {
    debug_assert_eq!(chunk.len(), ZERO_CHUNK);
    // SAFETY: both slices are exactly ZERO_CHUNK bytes long.
    unsafe {
        anchor_lang::solana_program::program_memory::sol_memcmp(chunk, &ZEROS, ZERO_CHUNK) == 0
    }
}

/// Extract the program (ELF) bytes from a BPF upgradeable loader Buffer
/// account's data, validating the state tag.
pub fn extract_buffer_program_bytes(data: &[u8]) -> Result<&[u8]> {
    require!(
        data.len() >= BUFFER_METADATA_SIZE,
        ClearSigningError::NotABuffer
    );
    let tag = u32::from_le_bytes(data[0..4].try_into().unwrap());
    require!(tag == BUFFER_STATE_TAG, ClearSigningError::NotABuffer);
    Ok(&data[BUFFER_METADATA_SIZE..])
}

/// SHA-256 (via the native `sol_sha256` syscall) of the program bytes with
/// trailing zeros trimmed — byte-identical to `solana-verify get-buffer-hash`
/// / `get-program-hash` (32-byte digest). Off-chain equivalent:
/// `sha256(trim_trailing_zeros(elf))`. Returns the digest and the trimmed
/// length (for logging, without trimming twice).
pub fn compute_program_hash(program_bytes: &[u8]) -> ([u8; 32], usize) {
    let trimmed = trim_trailing_zeros(program_bytes);
    (solana_sha256_hasher::hash(trimmed).to_bytes(), trimmed.len())
}

/// Decode one lowercase-hex nibble.
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Parse a 64-char lowercase-hex string into a 32-byte SHA-256 digest.
/// Returns `None` on wrong lengths and non-hex/uppercase characters.
pub fn parse_hex_hash(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (hex_nibble(b[2 * i])? << 4) | hex_nibble(b[2 * i + 1])?;
    }
    Some(out)
}

/// `parse_hex_hash` for `verify_buffer_hash`, which has always reported a
/// malformed digest as `BufferHashMismatch` (kept for error-code stability).
pub fn hex_to_hash(s: &str) -> Result<[u8; 32]> {
    parse_hex_hash(s).ok_or_else(|| error!(ClearSigningError::BufferHashMismatch))
}

/// Compare a computed digest against the signer-displayed hex digest. A
/// malformed `expected_hex` fails with `InvalidHashFormat`, a well-formed but
/// different one with `mismatch`. Logs both digests on mismatch.
pub fn check_hash(
    label: &str,
    computed: &[u8; 32],
    expected_hex: &str,
    mismatch: ClearSigningError,
) -> Result<()> {
    let expected =
        parse_hex_hash(expected_hex).ok_or_else(|| error!(ClearSigningError::InvalidHashFormat))?;
    if *computed != expected {
        msg!("{} hash mismatch", label);
        msg!("  computed: {}", hash_to_hex(computed));
        msg!("  expected: {}", expected_hex);
        return Err(mismatch.into());
    }
    Ok(())
}

/// SHA-256 (native `sol_sha256` syscall) of an account's **raw, untrimmed**
/// data — the generic commitment checked by `assert_account_hash`. Off-chain
/// equivalent: `sha256(account.data)`. Unlike program hashes, no trailing-zero
/// trimming is applied: for arbitrary account state, trailing zeros are
/// meaningful (e.g. a zero-valued integer field at the end of a struct).
pub fn compute_account_hash(data: &[u8]) -> [u8; 32] {
    solana_sha256_hasher::hash(data).to_bytes()
}

/// Parse a loader-v3 `Program` account, returning its `programdata_address`.
pub fn parse_program_account(data: &[u8]) -> Result<Pubkey> {
    require!(
        data.len() >= PROGRAM_ACCOUNT_SIZE,
        ClearSigningError::NotAProgram
    );
    let tag = u32::from_le_bytes(data[0..4].try_into().unwrap());
    require!(tag == PROGRAM_STATE_TAG, ClearSigningError::NotAProgram);
    Ok(Pubkey::new_from_array(data[4..36].try_into().unwrap()))
}

/// Extract the program (ELF) bytes from a loader-v3 `ProgramData` account's
/// data, validating the state tag.
pub fn extract_programdata_program_bytes(data: &[u8]) -> Result<&[u8]> {
    require!(
        data.len() >= PROGRAMDATA_METADATA_SIZE,
        ClearSigningError::NotAProgramData
    );
    let tag = u32::from_le_bytes(data[0..4].try_into().unwrap());
    require!(tag == PROGRAMDATA_STATE_TAG, ClearSigningError::NotAProgramData);
    Ok(&data[PROGRAMDATA_METADATA_SIZE..])
}

/// Encode a 32-byte digest as a lowercase-hex string (for log/error output).
pub fn hash_to_hex(hash: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &byte in hash.iter() {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0f) as usize] as char);
    }
    s
}

/// What the sibling Squads vote instruction must look like.
pub struct VoteExpectation {
    /// This program's id (its own instructions are allowed in the transaction).
    pub self_program: Pubkey,
    pub multisig: Pubkey,
    pub proposal: Pubkey,
    pub member: Pubkey,
    pub action: ProposalAction,
}

/// Enforce the strict shape of the outer transaction: every top-level
/// instruction must be either (a) this program, (b) the compute budget
/// program, or (c) the expected Squads vote instruction for exactly this
/// proposal, action, and member — and at least one such vote must be present.
///
/// If the transaction succeeds, the *only* effect it can have had on the
/// multisig is the vote the offline signer was shown.
pub fn validate_transaction_shape(
    top_level: &[Instruction],
    expectation: &VoteExpectation,
) -> Result<()> {
    let mut votes: usize = 0;
    for (i, ix) in top_level.iter().enumerate() {
        check_shape_instruction(
            i,
            &ix.program_id,
            &ix.data,
            |n| ix.accounts.get(n).map(|m| (m.pubkey, m.is_signer)),
            expectation,
            true,
            &mut votes,
        )?;
    }
    require!(votes >= 1, ClearSigningError::MissingVoteInstruction);
    Ok(())
}

/// The shape rule for one instruction, shared by the top-level check and the
/// embedded (CPI) checks: it must target this program (or, at top level only,
/// the compute budget program), or be exactly the expected Squads vote
/// (counted in `votes`). `account(n)` yields the n-th account's
/// `(pubkey, is_signer)`.
fn check_shape_instruction(
    i: usize,
    program_id: &Pubkey,
    data: &[u8],
    account: impl Fn(usize) -> Option<(Pubkey, bool)>,
    expectation: &VoteExpectation,
    allow_compute_budget: bool,
    votes: &mut usize,
) -> Result<()> {
    if *program_id == expectation.self_program
        || (allow_compute_budget && *program_id == COMPUTE_BUDGET_PROGRAM_ID)
    {
        return Ok(());
    }
    if *program_id != SQUADS_PROGRAM_ID {
        msg!("ix {}: forbidden program {}", i, program_id);
        return err!(ClearSigningError::ForbiddenInstruction);
    }
    if data.len() < 8 || data[..8] != expectation.action.discriminator() {
        msg!("ix {}: unexpected Squads instruction (wrong discriminator)", i);
        return err!(ClearSigningError::UnexpectedSquadsInstruction);
    }
    // ProposalVote accounts: 0 = multisig, 1 = member (signer), 2 = proposal.
    let (Some((multisig, _)), Some((member, member_is_signer)), Some((proposal, _))) =
        (account(0), account(1), account(2))
    else {
        return err!(ClearSigningError::MalformedVoteInstruction);
    };
    if multisig != expectation.multisig {
        msg!("ix {}: vote multisig {} != expected", i, multisig);
        return err!(ClearSigningError::VoteMultisigMismatch);
    }
    if member != expectation.member {
        msg!("ix {}: vote member {} != expected", i, member);
        return err!(ClearSigningError::VoteMemberMismatch);
    }
    if !member_is_signer {
        return err!(ClearSigningError::VoteMemberNotSigner);
    }
    if proposal != expectation.proposal {
        msg!("ix {}: vote proposal {} != expected", i, proposal);
        return err!(ClearSigningError::VoteProposalMismatch);
    }
    *votes += 1;
    Ok(())
}

// --- embedded instructions (verify_proposal_cpi) ---------------------------
//
// When the member is a programmatic signer (a PDA that only signs inside a
// CPI), the vote is not a top-level instruction: it is serialized inside the
// top-level instruction of the signer program (the "driver") that this CPI
// descends from. The functions below parse that driver instruction and apply
// the shape rule to the instruction list it will execute.
//
// The list is located by parsing the driver's own framing from the start of
// its instruction data, never from a caller-supplied offset: an offset chosen
// by whoever builds the payload can be aimed at look-alike bytes (an address
// table, another instruction's data) that the driver does not execute.

/// The ed25519 programmatic signer program: verifies the authority's
/// signature over an authorization message and CPIs the executor with the
/// authority's PDA as signer.
pub const ED25519_SIGNER_PROGRAM_ID: Pubkey =
    pubkey!("EdSigVfK1DkeMrjFNDMjwfQaJPhPTtX7jW8uPv3oKEgN");

/// The message executor the ed25519 signer hands its promoted signers to: it
/// CPIs every instruction of the execution message, in order.
pub const MESSAGE_EXECUTOR_PROGRAM_ID: Pubkey =
    pubkey!("ExecxgyHYsAXB4c5dZodV1zJZ9hqfsDCYkRDRATrpkFR");

/// ed25519 signer `Submit` / message executor `Execute` discriminators.
const SUBMIT_DISCRIMINATOR: u8 = 0;
const EXECUTE_DISCRIMINATOR: u8 = 0;
/// Vector `Advance` / `Passthrough` discriminators.
const VECTOR_ADVANCE_DISCRIMINATOR: u8 = 1;
const VECTOR_PASSTHROUGH_DISCRIMINATOR: u8 = 4;
/// Vector `Passthrough` accounts: `[vector PDA, instructions sysvar, payload...]`.
const VECTOR_FIRST_PAYLOAD_ACCOUNT: usize = 2;

/// Version prefix byte of a serialized Solana v1 message (SIMD-0385).
const V1_MESSAGE_PREFIX: u8 = 0x81;
/// Fixed part of a v1 message: prefix, 3-byte header, u32 config mask,
/// 32-byte lifetime specifier, instruction count, address count.
const V1_FIXED_SIZE: usize = 42;

fn bad_driver() -> Error {
    error!(ClearSigningError::MalformedDriverInstruction)
}

fn malformed() -> Error {
    error!(ClearSigningError::MalformedEmbeddedInstructions)
}

/// The fixed part and address table of a v1 message with a zero config mask
/// (a non-zero mask adds variable-size fields; neither program accepts one
/// here). `rest` is everything after the address table.
struct V1Prelude<'a> {
    num_signers: usize,
    num_instructions: usize,
    addresses: &'a [u8],
    rest: &'a [u8],
}

impl<'a> V1Prelude<'a> {
    fn parse(m: &'a [u8]) -> Option<Self> {
        if m.len() < V1_FIXED_SIZE || m[0] != V1_MESSAGE_PREFIX || m[4..8] != [0u8; 4] {
            return None;
        }
        let end = V1_FIXED_SIZE + 32 * usize::from(m[41]);
        Some(Self {
            num_signers: usize::from(m[1]),
            num_instructions: usize::from(m[40]),
            addresses: m.get(V1_FIXED_SIZE..end)?,
            rest: &m[end..],
        })
    }

    fn key(&self, index: u8) -> Option<Pubkey> {
        let start = usize::from(index) * 32;
        let bytes = self.addresses.get(start..start + 32)?;
        Some(Pubkey::new_from_array(bytes.try_into().unwrap()))
    }
}

/// Parse the data of an ed25519 signer `Submit` instruction and return the
/// serialized **execution message**: the v1 message whose instructions the
/// executor will CPI.
///
/// ```text
/// Submit data:  0x00 | n | n * (0x00 | 0x01 signature[64]) | authorization message
/// authorization message (v1, config mask 0, exactly one instruction):
///               ... | addresses | { program_id_index, num_accounts, data_len u16 }
///               | account indexes | Execute data
/// Execute data: 0x00 | execution message
/// ```
///
/// Every field is walked from the start and the data must be consumed
/// exactly, mirroring the signer program's own exact deserialization. The
/// authorization message's single instruction must target the message
/// executor's `Execute`.
pub fn eps_execution_message(submit_data: &[u8]) -> Result<&[u8]> {
    let (&discriminator, rest) = submit_data.split_first().ok_or_else(bad_driver)?;
    require!(
        discriminator == SUBMIT_DISCRIMINATOR,
        ClearSigningError::MalformedDriverInstruction
    );
    let (&num_signatures, mut rest) = rest.split_first().ok_or_else(bad_driver)?;
    for _ in 0..num_signatures {
        let (&tag, after) = rest.split_first().ok_or_else(bad_driver)?;
        rest = match tag {
            0 => after,
            1 => after.get(64..).ok_or_else(bad_driver)?,
            _ => return Err(bad_driver()),
        };
    }

    let authorization = V1Prelude::parse(rest).ok_or_else(bad_driver)?;
    require!(
        authorization.num_instructions == 1,
        ClearSigningError::MalformedDriverInstruction
    );
    let header = authorization.rest.get(..4).ok_or_else(bad_driver)?;
    let program_id = authorization.key(header[0]).ok_or_else(bad_driver)?;
    let num_accounts = usize::from(header[1]);
    let data_len = usize::from(u16::from_le_bytes([header[2], header[3]]));
    let execute_data = authorization
        .rest
        .get(4 + num_accounts..)
        .ok_or_else(bad_driver)?;
    require!(
        execute_data.len() == data_len && program_id == MESSAGE_EXECUTOR_PROGRAM_ID,
        ClearSigningError::MalformedDriverInstruction
    );
    let (&discriminator, execution_message) = execute_data.split_first().ok_or_else(bad_driver)?;
    require!(
        discriminator == EXECUTE_DISCRIMINATOR,
        ClearSigningError::MalformedDriverInstruction
    );
    Ok(execution_message)
}

fn finish_embedded(votes: usize, found_self: bool) -> Result<()> {
    require!(found_self, ClearSigningError::EmbeddedSelfInstructionMissing);
    require!(votes >= 1, ClearSigningError::MissingVoteInstruction);
    Ok(())
}

/// Apply the shape rule to every instruction of a serialized Solana **v1
/// message** (the execution message of the ed25519 programmatic signer):
///
/// ```text
/// 0x81 | num_required_signatures, num_readonly_signed, num_readonly_unsigned
///      | config mask u32 (must be 0) | lifetime [32] | num_instructions | num_addresses
///      | addresses [32 * num_addresses]
///      | headers   [num_instructions * { program_id_index, num_accounts, data_len u16 }]
///      | payloads  [per instruction: account indexes, then data]
/// ```
///
/// `message` must be exactly the message. An account is a signer of an
/// embedded instruction iff its index is below `num_required_signatures`.
/// The list must also contain this very invocation (`own_data`).
pub fn validate_embedded_v1_message(
    message: &[u8],
    own_data: &[u8],
    expectation: &VoteExpectation,
) -> Result<()> {
    let m = V1Prelude::parse(message).ok_or_else(malformed)?;
    let mut cursor = 4 * m.num_instructions;
    let headers = m.rest.get(..cursor).ok_or_else(malformed)?;

    let mut votes = 0;
    let mut found_self = false;
    for (i, header) in headers.chunks_exact(4).enumerate() {
        let program_id = m.key(header[0]).ok_or_else(malformed)?;
        let num_accounts = usize::from(header[1]);
        let data_len = usize::from(u16::from_le_bytes([header[2], header[3]]));
        let indexes = m.rest.get(cursor..cursor + num_accounts).ok_or_else(malformed)?;
        cursor += num_accounts;
        let ix_data = m.rest.get(cursor..cursor + data_len).ok_or_else(malformed)?;
        cursor += data_len;
        // Every referenced account must resolve, even ones the rule ignores.
        for &index in indexes {
            m.key(index).ok_or_else(malformed)?;
        }
        check_shape_instruction(
            i,
            &program_id,
            ix_data,
            |n| {
                let index = *indexes.get(n)?;
                Some((m.key(index)?, usize::from(index) < m.num_signers))
            },
            expectation,
            false,
            &mut votes,
        )?;
        found_self |= program_id == expectation.self_program && ix_data == own_data;
    }
    require!(
        cursor == m.rest.len(),
        ClearSigningError::EmbeddedTrailingBytes
    );
    finish_embedded(votes, found_self)
}

/// Apply the shape rule to every sub-instruction of a Vector `Passthrough`,
/// given that top-level instruction's data and accounts:
///
/// ```text
/// data:     0x04 | count u8 | count * { num_accounts u8, data_len u16, data }
/// accounts: vector PDA, instructions sysvar,
///           then per sub-instruction: program account, its num_accounts accounts
/// ```
///
/// The vector PDA (account 0) must be the expected member. Data and accounts
/// must be consumed exactly, as Vector itself requires.
///
/// The top-level signer flags describe the transaction, not the CPI: Vector
/// promotes its PDA to a signer in every sub-instruction that lists it, so
/// the member counts as a signer of the embedded vote.
pub fn validate_vector_passthrough(
    data: &[u8],
    accounts: &[anchor_lang::solana_program::instruction::AccountMeta],
    own_data: &[u8],
    expectation: &VoteExpectation,
) -> Result<()> {
    require!(
        data.first() == Some(&VECTOR_PASSTHROUGH_DISCRIMINATOR)
            && accounts.first().map(|m| m.pubkey) == Some(expectation.member),
        ClearSigningError::MalformedDriverInstruction
    );
    let count = usize::from(*data.get(1).ok_or_else(malformed)?);
    let mut cursor = 2;
    let mut account_cursor = VECTOR_FIRST_PAYLOAD_ACCOUNT;

    let mut votes = 0;
    let mut found_self = false;
    for i in 0..count {
        let header = data.get(cursor..cursor + 3).ok_or_else(malformed)?;
        let num_accounts = usize::from(header[0]);
        let data_len = usize::from(u16::from_le_bytes([header[1], header[2]]));
        cursor += 3;
        let ix_data = data.get(cursor..cursor + data_len).ok_or_else(malformed)?;
        cursor += data_len;
        let program_id = accounts.get(account_cursor).ok_or_else(malformed)?.pubkey;
        let ix_accounts = accounts
            .get(account_cursor + 1..account_cursor + 1 + num_accounts)
            .ok_or_else(malformed)?;
        account_cursor += 1 + num_accounts;
        check_shape_instruction(
            i,
            &program_id,
            ix_data,
            |n| {
                let meta = ix_accounts.get(n)?;
                Some((
                    meta.pubkey,
                    meta.is_signer || meta.pubkey == expectation.member,
                ))
            },
            expectation,
            false,
            &mut votes,
        )?;
        found_self |= program_id == expectation.self_program && ix_data == own_data;
    }
    require!(
        cursor == data.len() && account_cursor == accounts.len(),
        ClearSigningError::EmbeddedTrailingBytes
    );
    finish_embedded(votes, found_self)
}

/// One Vector `Advance` authorizes every later `Passthrough` of the same
/// transaction, so the transaction's other instructions of the Vector
/// program must all be `Advance`s: a second `Passthrough` would use the
/// member's signature outside the list checked above.
pub fn check_vector_sibling(program_id: &Pubkey, data: &[u8], vector_program: &Pubkey) -> Result<()> {
    if program_id == vector_program && data.first() != Some(&VECTOR_ADVANCE_DISCRIMINATOR) {
        return err!(ClearSigningError::ForbiddenDriverInstruction);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::squads::{
        MultisigCompiledInstruction, MultisigMessageAddressTableLookup,
        IX_PROPOSAL_APPROVE, IX_PROPOSAL_REJECT,
    };
    use crate::ExpectedAccountMeta;
    use anchor_lang::solana_program::instruction::AccountMeta;

    fn pk(n: u8) -> Pubkey {
        Pubkey::new_from_array([n; 32])
    }

    fn code(res: Result<()>) -> u32 {
        match res.unwrap_err() {
            anchor_lang::error::Error::AnchorError(e) => e.error_code_number,
            other => panic!("expected AnchorError, got {other:?}"),
        }
    }

    fn err_code(e: ClearSigningError) -> u32 {
        anchor_lang::error::ERROR_CODE_OFFSET + e as u32
    }

    /// Static layout: [ws:1, rs:2, wn:3, rn:4, program:9]
    /// -> num_signers=2, num_writable_signers=1, num_writable_non_signers=1.
    fn simple_message() -> VaultTransactionMessage {
        VaultTransactionMessage {
            num_signers: 2,
            num_writable_signers: 1,
            num_writable_non_signers: 1,
            account_keys: vec![pk(1), pk(2), pk(3), pk(4), pk(9)],
            instructions: vec![
                MultisigCompiledInstruction {
                    program_id_index: 4,
                    account_indexes: vec![0, 2, 3],
                    data: vec![10, 11, 12],
                },
                MultisigCompiledInstruction {
                    program_id_index: 4,
                    account_indexes: vec![1],
                    data: vec![],
                },
            ],
            address_table_lookups: vec![],
        }
    }

    fn simple_expected() -> Vec<ExpectedInstruction> {
        vec![
            ExpectedInstruction {
                program_id: pk(9),
                accounts: vec![
                    ExpectedAccountMeta { pubkey: pk(1), is_signer: true, is_writable: true },
                    ExpectedAccountMeta { pubkey: pk(3), is_signer: false, is_writable: true },
                    ExpectedAccountMeta { pubkey: pk(4), is_signer: false, is_writable: false },
                ],
                data: vec![10, 11, 12],
            },
            ExpectedInstruction {
                program_id: pk(9),
                accounts: vec![ExpectedAccountMeta {
                    pubkey: pk(2),
                    is_signer: true,
                    is_writable: false,
                }],
                data: vec![],
            },
        ]
    }

    #[test]
    fn matching_instructions_pass() {
        let message = simple_message();
        let keys = AccountKeys::resolve(&message, &[]).unwrap();
        validate_instructions(&message, &keys, &simple_expected()).unwrap();
    }

    #[test]
    fn detects_each_mismatch() {
        let message = simple_message();
        let keys = AccountKeys::resolve(&message, &[]).unwrap();

        let mut e = simple_expected();
        e[0].data[1] ^= 1;
        assert_eq!(
            code(validate_instructions(&message, &keys, &e)),
            err_code(ClearSigningError::DataMismatch)
        );

        let mut e = simple_expected();
        e[0].program_id = pk(8);
        assert_eq!(
            code(validate_instructions(&message, &keys, &e)),
            err_code(ClearSigningError::ProgramIdMismatch)
        );

        let mut e = simple_expected();
        e[0].accounts[1].pubkey = pk(4);
        assert_eq!(
            code(validate_instructions(&message, &keys, &e)),
            err_code(ClearSigningError::AccountKeyMismatch)
        );

        let mut e = simple_expected();
        e[0].accounts[2].is_writable = true;
        assert_eq!(
            code(validate_instructions(&message, &keys, &e)),
            err_code(ClearSigningError::AccountWritableMismatch)
        );

        let mut e = simple_expected();
        e[1].accounts[0].is_signer = false;
        assert_eq!(
            code(validate_instructions(&message, &keys, &e)),
            err_code(ClearSigningError::AccountSignerMismatch)
        );

        let mut e = simple_expected();
        e[0].accounts.pop();
        assert_eq!(
            code(validate_instructions(&message, &keys, &e)),
            err_code(ClearSigningError::AccountCountMismatch)
        );

        let mut e = simple_expected();
        e.pop();
        assert_eq!(
            code(validate_instructions(&message, &keys, &e)),
            err_code(ClearSigningError::InstructionCountMismatch)
        );
    }

    #[test]
    fn resolves_lookup_table_keys() {
        let mut message = simple_message();
        message.address_table_lookups = vec![MultisigMessageAddressTableLookup {
            account_key: pk(50),
            writable_indexes: vec![1],
            readonly_indexes: vec![0],
        }];
        // Combined index space: 0..4 static, 5 = table[1] (writable), 6 = table[0] (readonly).
        message.instructions.push(MultisigCompiledInstruction {
            program_id_index: 4,
            account_indexes: vec![5, 6],
            data: vec![7],
        });

        let table = vec![pk(60), pk(61)];
        let keys = AccountKeys::resolve(&message, &[table]).unwrap();
        assert_eq!(keys.get(5).unwrap(), &pk(61));
        assert_eq!(keys.get(6).unwrap(), &pk(60));
        assert!(keys.is_writable(5));
        assert!(!keys.is_writable(6));
        assert!(!keys.is_signer(5) && !keys.is_signer(6));

        let mut expected = simple_expected();
        expected.push(ExpectedInstruction {
            program_id: pk(9),
            accounts: vec![
                ExpectedAccountMeta { pubkey: pk(61), is_signer: false, is_writable: true },
                ExpectedAccountMeta { pubkey: pk(60), is_signer: false, is_writable: false },
            ],
            data: vec![7],
        });
        validate_instructions(&message, &keys, &expected).unwrap();
    }

    #[test]
    fn lookup_table_errors() {
        let mut message = simple_message();
        message.address_table_lookups = vec![MultisigMessageAddressTableLookup {
            account_key: pk(50),
            writable_indexes: vec![5], // out of bounds for a 2-entry table
            readonly_indexes: vec![],
        }];
        assert_eq!(
            code(AccountKeys::resolve(&message, &[vec![pk(60), pk(61)]]).map(|_| ())),
            err_code(ClearSigningError::LookupTableIndexOutOfBounds)
        );
        // Wrong number of tables supplied.
        assert_eq!(
            code(AccountKeys::resolve(&message, &[]).map(|_| ())),
            err_code(ClearSigningError::LookupTableCountMismatch)
        );
    }

    #[test]
    fn parses_lookup_table_account() {
        let mut data = vec![0u8; LOOKUP_TABLE_META_SIZE];
        data[0] = 1; // ProgramState::LookupTable
        data.extend_from_slice(pk(60).as_ref());
        data.extend_from_slice(pk(61).as_ref());
        assert_eq!(parse_lookup_table_addresses(&data).unwrap(), vec![pk(60), pk(61)]);

        // Uninitialized state tag.
        let mut bad = data.clone();
        bad[0] = 0;
        assert!(parse_lookup_table_addresses(&bad).is_err());

        // Truncated addresses.
        let bad = &data[..data.len() - 5];
        assert!(parse_lookup_table_addresses(bad).is_err());
    }

    #[test]
    fn out_of_bounds_account_index() {
        let mut message = simple_message();
        message.instructions[0].account_indexes = vec![0, 2, 200];
        let keys = AccountKeys::resolve(&message, &[]).unwrap();
        assert_eq!(
            code(validate_instructions(&message, &keys, &simple_expected())),
            err_code(ClearSigningError::AccountIndexOutOfBounds)
        );
    }

    // --- buffer hash tests ---

    #[test]
    fn trims_only_trailing_zeros() {
        assert_eq!(trim_trailing_zeros(&[0, 1, 2, 0, 0]), &[0, 1, 2]);
        assert_eq!(trim_trailing_zeros(&[1, 2, 3]), &[1, 2, 3]);
        assert_eq!(trim_trailing_zeros(&[0, 0, 0]), &[] as &[u8]);
        assert_eq!(trim_trailing_zeros(&[]), &[] as &[u8]);
    }

    /// The chunked scan must agree with a plain byte-wise trim at every
    /// alignment of the last non-zero byte relative to the chunk boundaries.
    #[test]
    fn chunked_trim_matches_bytewise() {
        fn reference(b: &[u8]) -> usize {
            b.iter().rposition(|&x| x != 0).map(|i| i + 1).unwrap_or(0)
        }
        for total in [0, 1, ZERO_CHUNK - 1, ZERO_CHUNK, ZERO_CHUNK + 1, 3 * ZERO_CHUNK + 7] {
            let mut positions = vec![None];
            for p in [0, 1, ZERO_CHUNK - 1, ZERO_CHUNK, ZERO_CHUNK + 1, 2 * ZERO_CHUNK + 3] {
                if p < total {
                    positions.push(Some(p));
                }
            }
            if total > 0 {
                positions.push(Some(total - 1));
            }
            for pos in positions {
                let mut data = vec![0u8; total];
                if let Some(p) = pos {
                    data[p] = 0x5a;
                }
                assert_eq!(
                    trim_trailing_zeros(&data).len(),
                    reference(&data),
                    "total {total}, nonzero at {pos:?}"
                );
                // An extra non-zero byte in an earlier chunk must not matter
                // once a later one exists.
                if let Some(p) = pos {
                    if p > 0 {
                        data[0] = 0x01;
                        assert_eq!(trim_trailing_zeros(&data).len(), reference(&data));
                    }
                }
            }
        }
    }

    #[test]
    fn sha256_matches_reference_and_solana_verify_convention() {
        use sha2::{Digest, Sha256};
        for input in [
            &b""[..],
            b"abc",
            &[0u8; 200],
            &[7u8; 5000],
        ] {
            let expected: [u8; 32] = Sha256::digest(trim_trailing_zeros(input)).into();
            assert_eq!(compute_program_hash(input).0, expected);
        }
        // sha256("abc") = ba7816bf... — the solana-verify hashing convention.
        assert_eq!(
            hash_to_hex(&compute_program_hash(b"abc").0),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // Trailing zeros must not affect the hash.
        assert_eq!(
            compute_program_hash(b"abc\x00\x00\x00"),
            (compute_program_hash(b"abc").0, 3)
        );
    }

    #[test]
    fn hex_hash_round_trip() {
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(b"clear-signing").into();
        let hex = hash_to_hex(&digest);
        assert_eq!(hex.len(), 64);
        assert_eq!(hex_to_hash(&hex).unwrap(), digest);
        assert_eq!(hash_to_hex(&compute_program_hash(b"abc\x00\x00").0),
                   hash_to_hex(&compute_program_hash(b"abc").0));
    }

    #[test]
    fn hex_to_hash_rejects_bad_input() {
        let ok = "a".repeat(64);
        assert!(hex_to_hash(&ok).is_ok());
        // wrong length
        assert_eq!(code(hex_to_hash(&"a".repeat(63)).map(|_| ())),
                   err_code(ClearSigningError::BufferHashMismatch));
        // uppercase / non-hex
        let mut bad = "a".repeat(64); bad.replace_range(0..1, "A");
        assert_eq!(code(hex_to_hash(&bad).map(|_| ())),
                   err_code(ClearSigningError::BufferHashMismatch));
        let mut bad2 = "a".repeat(64); bad2.replace_range(5..6, "g");
        assert!(hex_to_hash(&bad2).is_err());
    }

    #[test]
    fn extracts_buffer_bytes() {
        // 4-byte tag (1 = Buffer) + 33-byte authority option + program bytes.
        let mut data = vec![0u8; BUFFER_METADATA_SIZE];
        data[0] = 1;
        data.extend_from_slice(b"elf-bytes");
        assert_eq!(extract_buffer_program_bytes(&data).unwrap(), b"elf-bytes");

        // Wrong state tag (e.g. 3 = ProgramData) is rejected.
        let mut bad = data.clone();
        bad[0] = 3;
        assert_eq!(
            code(extract_buffer_program_bytes(&bad).map(|_| ())),
            err_code(ClearSigningError::NotABuffer)
        );
        // Too short.
        assert_eq!(
            code(extract_buffer_program_bytes(&[1, 0, 0]).map(|_| ())),
            err_code(ClearSigningError::NotABuffer)
        );
    }

    // --- account hash / program revision tests ---

    #[test]
    fn account_hash_is_untrimmed_sha256() {
        use sha2::{Digest, Sha256};
        for input in [&b""[..], b"abc", b"abc\x00\x00", &[0u8; 300]] {
            let expected: [u8; 32] = Sha256::digest(input).into();
            assert_eq!(compute_account_hash(input), expected);
        }
        // Trailing zeros are significant for raw account state.
        assert_ne!(compute_account_hash(b"abc\x00"), compute_account_hash(b"abc"));
    }

    #[test]
    fn check_hash_distinguishes_format_and_mismatch() {
        let h = compute_account_hash(b"state");
        let hex = hash_to_hex(&h);
        check_hash("t", &h, &hex, ClearSigningError::AccountHashMismatch).unwrap();

        let other = hash_to_hex(&compute_account_hash(b"other"));
        assert_eq!(
            code(check_hash("t", &h, &other, ClearSigningError::AccountHashMismatch)),
            err_code(ClearSigningError::AccountHashMismatch)
        );
        assert_eq!(
            code(check_hash("t", &h, &other, ClearSigningError::ProgramHashMismatch)),
            err_code(ClearSigningError::ProgramHashMismatch)
        );
        for bad in [&hex[..63], &hex.to_uppercase(), ""] {
            assert_eq!(
                code(check_hash("t", &h, bad, ClearSigningError::AccountHashMismatch)),
                err_code(ClearSigningError::InvalidHashFormat)
            );
        }
    }

    #[test]
    fn parses_program_account() {
        let mut data = vec![2u8, 0, 0, 0];
        data.extend_from_slice(pk(77).as_ref());
        assert_eq!(parse_program_account(&data).unwrap(), pk(77));

        // Buffer / ProgramData / Uninitialized tags are rejected.
        for tag in [0u8, 1, 3] {
            let mut bad = data.clone();
            bad[0] = tag;
            assert_eq!(
                code(parse_program_account(&bad).map(|_| ())),
                err_code(ClearSigningError::NotAProgram)
            );
        }
        assert_eq!(
            code(parse_program_account(&data[..35]).map(|_| ())),
            err_code(ClearSigningError::NotAProgram)
        );
    }

    #[test]
    fn extracts_programdata_bytes() {
        // 4-byte tag (3 = ProgramData) + 8-byte slot + 33-byte authority option.
        let mut data = vec![0u8; PROGRAMDATA_METADATA_SIZE];
        data[0] = 3;
        data[4] = 42; // slot
        data[12] = 1; // Some(authority)
        data[13..45].copy_from_slice(pk(5).as_ref());
        data.extend_from_slice(b"elf-bytes\x00\x00");
        assert_eq!(extract_programdata_program_bytes(&data).unwrap(), b"elf-bytes\x00\x00");
        // Program hash uses the solana-verify trimming convention.
        assert_eq!(
            compute_program_hash(extract_programdata_program_bytes(&data).unwrap()),
            (compute_program_hash(b"elf-bytes").0, 9)
        );

        // A Buffer is not a ProgramData.
        let mut bad = data.clone();
        bad[0] = 1;
        assert_eq!(
            code(extract_programdata_program_bytes(&bad).map(|_| ())),
            err_code(ClearSigningError::NotAProgramData)
        );
        assert_eq!(
            code(extract_programdata_program_bytes(&data[..44]).map(|_| ())),
            err_code(ClearSigningError::NotAProgramData)
        );
    }

    #[test]
    fn new_error_codes_are_appended() {
        // Existing codes must not move when variants are added.
        assert_eq!(err_code(ClearSigningError::ProposalIndexMismatch), 6036);
        assert_eq!(err_code(ClearSigningError::InvalidHashFormat), 6037);
        assert_eq!(err_code(ClearSigningError::ProgramHashMismatch), 6047);
    }

    // --- transaction shape tests ---

    fn expectation() -> VoteExpectation {
        VoteExpectation {
            self_program: pk(100),
            multisig: pk(101),
            proposal: pk(102),
            member: pk(103),
            action: ProposalAction::Approve,
        }
    }

    fn self_ix() -> Instruction {
        Instruction { program_id: pk(100), accounts: vec![], data: vec![0xAA] }
    }

    fn vote_ix(disc: [u8; 8], multisig: Pubkey, member: Pubkey, proposal: Pubkey) -> Instruction {
        Instruction {
            program_id: SQUADS_PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(multisig, false),
                AccountMeta::new(member, true),
                AccountMeta::new(proposal, false),
            ],
            data: [disc.to_vec(), vec![0]].concat(), // discriminator + memo: None
        }
    }

    fn ok_vote() -> Instruction {
        vote_ix(IX_PROPOSAL_APPROVE, pk(101), pk(103), pk(102))
    }

    #[test]
    fn accepts_expected_shape() {
        let cb = Instruction {
            program_id: COMPUTE_BUDGET_PROGRAM_ID,
            accounts: vec![],
            data: vec![2, 64, 66, 15, 0],
        };
        validate_transaction_shape(&[cb, self_ix(), ok_vote()], &expectation()).unwrap();
        // Duplicate matching votes are tolerated (Squads itself rejects re-votes).
        validate_transaction_shape(&[self_ix(), ok_vote(), ok_vote()], &expectation()).unwrap();
    }

    #[test]
    fn rejects_bad_shapes() {
        let exp = expectation();

        // No vote at all.
        assert_eq!(
            code(validate_transaction_shape(&[self_ix()], &exp)),
            err_code(ClearSigningError::MissingVoteInstruction)
        );

        // A foreign program smuggled in.
        let foreign = Instruction { program_id: pk(200), accounts: vec![], data: vec![] };
        assert_eq!(
            code(validate_transaction_shape(&[self_ix(), ok_vote(), foreign], &exp)),
            err_code(ClearSigningError::ForbiddenInstruction)
        );

        // Wrong vote kind (reject instead of approve).
        let wrong_kind = vote_ix(IX_PROPOSAL_REJECT, pk(101), pk(103), pk(102));
        assert_eq!(
            code(validate_transaction_shape(&[self_ix(), wrong_kind], &exp)),
            err_code(ClearSigningError::UnexpectedSquadsInstruction)
        );

        // Vote for a different proposal.
        let wrong_proposal = vote_ix(IX_PROPOSAL_APPROVE, pk(101), pk(103), pk(66));
        assert_eq!(
            code(validate_transaction_shape(&[self_ix(), wrong_proposal], &exp)),
            err_code(ClearSigningError::VoteProposalMismatch)
        );

        // Vote by a different member.
        let wrong_member = vote_ix(IX_PROPOSAL_APPROVE, pk(101), pk(66), pk(102));
        assert_eq!(
            code(validate_transaction_shape(&[self_ix(), wrong_member], &exp)),
            err_code(ClearSigningError::VoteMemberMismatch)
        );

        // Wrong multisig.
        let wrong_multisig = vote_ix(IX_PROPOSAL_APPROVE, pk(66), pk(103), pk(102));
        assert_eq!(
            code(validate_transaction_shape(&[self_ix(), wrong_multisig], &exp)),
            err_code(ClearSigningError::VoteMultisigMismatch)
        );

        // Member not a signer.
        let mut unsigned = ok_vote();
        unsigned.accounts[1].is_signer = false;
        assert_eq!(
            code(validate_transaction_shape(&[self_ix(), unsigned], &exp)),
            err_code(ClearSigningError::VoteMemberNotSigner)
        );

        // A matching vote does not excuse a second, non-matching Squads ix.
        let sneaky = vote_ix(IX_PROPOSAL_APPROVE, pk(101), pk(103), pk(66));
        assert_eq!(
            code(validate_transaction_shape(&[self_ix(), ok_vote(), sneaky], &exp)),
            err_code(ClearSigningError::VoteProposalMismatch)
        );
    }

    // --- embedded (verify_proposal_cpi) tests ---

    const OWN: &[u8] = b"verify-proposal-cpi-own-data";

    /// (program, [(pubkey, is_signer)], data)
    type TestIx = (Pubkey, Vec<Pubkey>, Vec<u8>);

    fn embedded_self() -> TestIx {
        (pk(100), vec![pk(102), pk(104), pk(103)], OWN.to_vec())
    }
    fn embedded_vote(proposal: Pubkey) -> TestIx {
        (
            SQUADS_PROGRAM_ID,
            vec![pk(101), pk(103), proposal],
            [IX_PROPOSAL_APPROVE.to_vec(), vec![0]].concat(),
        )
    }

    /// Serialize a v1 message: `signers` first in the key table.
    fn v1_message(signers: &[Pubkey], ixs: &[TestIx]) -> Vec<u8> {
        let mut keys: Vec<Pubkey> = signers.to_vec();
        let mut index = |k: &Pubkey, keys: &mut Vec<Pubkey>| -> u8 {
            if let Some(i) = keys.iter().position(|x| x == k) {
                return i as u8;
            }
            keys.push(*k);
            (keys.len() - 1) as u8
        };
        let mut headers = vec![];
        let mut payloads = vec![];
        for (program, accounts, data) in ixs {
            let idxs: Vec<u8> = accounts.iter().map(|a| index(a, &mut keys)).collect();
            headers.push(index(program, &mut keys));
            headers.push(idxs.len() as u8);
            headers.extend_from_slice(&(data.len() as u16).to_le_bytes());
            payloads.extend_from_slice(&idxs);
            payloads.extend_from_slice(data);
        }
        let mut m = vec![0x81, signers.len() as u8, 0, 0];
        m.extend_from_slice(&0u32.to_le_bytes());
        m.extend_from_slice(&[0xAB; 32]);
        m.push(ixs.len() as u8);
        m.push(keys.len() as u8);
        for k in &keys {
            m.extend_from_slice(k.as_ref());
        }
        m.extend_from_slice(&headers);
        m.extend_from_slice(&payloads);
        m
    }

    fn v1(signers: &[Pubkey], ixs: &[TestIx]) -> Result<()> {
        validate_embedded_v1_message(&v1_message(signers, ixs), OWN, &expectation())
    }

    #[test]
    fn v1_accepts_verify_plus_vote() {
        v1(&[pk(103)], &[embedded_self(), embedded_vote(pk(102))]).unwrap();
        // Other instructions of this program (e.g. assert_*) are fine too.
        let assert_ix = (pk(100), vec![pk(55)], b"assert".to_vec());
        v1(&[pk(103)], &[assert_ix, embedded_self(), embedded_vote(pk(102))]).unwrap();
    }

    #[test]
    fn v1_rejects_bad_content() {
        let signers = [pk(103)];
        // Vote on another proposal.
        assert_eq!(
            code(v1(&signers, &[embedded_self(), embedded_vote(pk(66))])),
            err_code(ClearSigningError::VoteProposalMismatch)
        );
        // No vote.
        assert_eq!(
            code(v1(&signers, &[embedded_self()])),
            err_code(ClearSigningError::MissingVoteInstruction)
        );
        // A foreign program next to the vote.
        let foreign = (pk(200), vec![], b"x".to_vec());
        assert_eq!(
            code(v1(&signers, &[embedded_self(), embedded_vote(pk(102)), foreign])),
            err_code(ClearSigningError::ForbiddenInstruction)
        );
        // Compute budget is tolerated at top level only, not in an embedded list.
        let budget = (COMPUTE_BUDGET_PROGRAM_ID, vec![], vec![2, 0, 0, 0, 0]);
        assert_eq!(
            code(v1(&signers, &[budget, embedded_self(), embedded_vote(pk(102))])),
            err_code(ClearSigningError::ForbiddenInstruction)
        );
        // A second, different Squads vote.
        assert_eq!(
            code(v1(&signers, &[embedded_self(), embedded_vote(pk(102)), embedded_vote(pk(66))])),
            err_code(ClearSigningError::VoteProposalMismatch)
        );
        // Member outside the signer region of the embedded message.
        assert_eq!(
            code(v1(&[pk(77)], &[embedded_self(), embedded_vote(pk(102))])),
            err_code(ClearSigningError::VoteMemberNotSigner)
        );
        // This invocation is not in the list.
        let other_self = (pk(100), vec![], b"some-other-verify".to_vec());
        assert_eq!(
            code(v1(&signers, &[other_self, embedded_vote(pk(102))])),
            err_code(ClearSigningError::EmbeddedSelfInstructionMissing)
        );
    }

    #[test]
    fn v1_rejects_bad_framing() {
        let exp = expectation();
        let message = v1_message(&[pk(103)], &[embedded_self(), embedded_vote(pk(102))]);
        let check = |m: &[u8]| code(validate_embedded_v1_message(m, OWN, &exp));
        let malformed = err_code(ClearSigningError::MalformedEmbeddedInstructions);

        // Not a v1 message, truncated header, truncated payload.
        assert_eq!(check(&message[1..]), malformed);
        assert_eq!(check(&message[..20]), malformed);
        assert_eq!(check(&message[..message.len() - 1]), malformed);
        // Trailing bytes after the message.
        let mut trailing = message.clone();
        trailing.push(0);
        assert_eq!(
            check(&trailing),
            err_code(ClearSigningError::EmbeddedTrailingBytes)
        );
        // Non-zero config mask.
        let mut masked = message.clone();
        masked[4] = 1;
        assert_eq!(check(&masked), malformed);
        // Account index beyond the key table (last payload = vote: 3 indexes + 9 data bytes).
        let mut oob = message.clone();
        let n = oob.len();
        oob[n - 10] = 250;
        assert_eq!(check(&oob), malformed);
    }

    /// ed25519 signer `Submit` data around an execution message: `sigs` are the
    /// per-signer presence flags, `junk_keys` extra authorization-message
    /// addresses (bytes an attacker fully controls).
    fn submit_data(execution_message: &[u8], sigs: &[bool], junk_keys: &[[u8; 32]]) -> Vec<u8> {
        let mut execute = vec![0u8];
        execute.extend_from_slice(execution_message);
        // Authorization message: keys = [authority, executor, junk...], one instruction.
        let mut auth = vec![0x81, sigs.len() as u8, 0, 0];
        auth.extend_from_slice(&0u32.to_le_bytes());
        auth.extend_from_slice(&[0; 32]);
        auth.push(1);
        auth.push(2 + junk_keys.len() as u8);
        auth.extend_from_slice(pk(103).as_ref());
        auth.extend_from_slice(MESSAGE_EXECUTOR_PROGRAM_ID.as_ref());
        for k in junk_keys {
            auth.extend_from_slice(k);
        }
        auth.extend_from_slice(&[1, 1]);
        auth.extend_from_slice(&(execute.len() as u16).to_le_bytes());
        auth.push(0);
        auth.extend_from_slice(&execute);

        let mut data = vec![0u8, sigs.len() as u8];
        for &present in sigs {
            if present {
                data.push(1);
                data.extend_from_slice(&[0x55; 64]);
            } else {
                data.push(0);
            }
        }
        data.extend_from_slice(&auth);
        data
    }

    #[test]
    fn eps_locates_execution_message() {
        let message = v1_message(&[pk(103)], &[embedded_self(), embedded_vote(pk(102))]);
        // The location does not depend on which signatures are present.
        for sigs in [&[true][..], &[false], &[true, false, true]] {
            let data = submit_data(&message, sigs, &[]);
            assert_eq!(eps_execution_message(&data).unwrap(), &message[..]);
        }
        // Extra addresses in the authorization message do not move what is
        // found: the execution message is located by walking the framing.
        let junk = v1_message(&[pk(103)], &[embedded_self(), embedded_vote(pk(66))]);
        let mut keys = vec![];
        for chunk in junk.chunks(32) {
            let mut k = [0u8; 32];
            k[..chunk.len()].copy_from_slice(chunk);
            keys.push(k);
        }
        let data = submit_data(&message, &[true], &keys);
        assert_eq!(eps_execution_message(&data).unwrap(), &message[..]);
    }

    #[test]
    fn eps_rejects_bad_framing() {
        let message = v1_message(&[pk(103)], &[embedded_self(), embedded_vote(pk(102))]);
        let data = submit_data(&message, &[true], &[]);
        let bad = err_code(ClearSigningError::MalformedDriverInstruction);
        let check = |d: &[u8]| code(eps_execution_message(d).map(|_| ()));

        assert_eq!(check(&[]), bad);
        // Not a Submit.
        let mut other = data.clone();
        other[0] = 1;
        assert_eq!(check(&other), bad);
        // Invalid signature option tag.
        let mut tag = data.clone();
        tag[2] = 2;
        assert_eq!(check(&tag), bad);
        // Truncated, and trailing bytes after the Execute data.
        assert_eq!(check(&data[..data.len() - 1]), bad);
        let mut trailing = data.clone();
        trailing.push(0);
        assert_eq!(check(&trailing), bad);
        // Authorization message offsets: prefix at 67, instruction count at 107,
        // executor key at 109 + 32, Execute discriminator right before the message.
        let auth = 2 + 65;
        let mut two = data.clone();
        two[auth + 40] = 2;
        assert_eq!(check(&two), bad);
        let mut masked = data.clone();
        masked[auth + 4] = 1;
        assert_eq!(check(&masked), bad);
        let mut executor = data.clone();
        executor[auth + 42 + 32] ^= 1;
        assert_eq!(check(&executor), bad);
        let mut not_execute = data.clone();
        let d = data.len() - message.len() - 1;
        not_execute[d] = 1;
        assert_eq!(check(&not_execute), bad);
    }

    /// Vector `Passthrough`: data `[4, count, entries...]`, accounts
    /// `[vector pda, sysvar, (program, accounts...)*]`.
    fn passthrough(ixs: &[TestIx]) -> (Vec<u8>, Vec<AccountMeta>) {
        let mut data = vec![4u8, ixs.len() as u8];
        let mut metas = vec![
            AccountMeta::new(pk(103), false),
            AccountMeta::new_readonly(pk(9), false),
        ];
        for (program, accounts, ix_data) in ixs {
            data.push(accounts.len() as u8);
            data.extend_from_slice(&(ix_data.len() as u16).to_le_bytes());
            data.extend_from_slice(ix_data);
            metas.push(AccountMeta::new_readonly(*program, false));
            // No signer flags: the programmatic signer is promoted only in the CPI.
            metas.extend(accounts.iter().map(|a| AccountMeta::new(*a, false)));
        }
        (data, metas)
    }

    fn pt(ixs: &[TestIx]) -> Result<()> {
        let (data, metas) = passthrough(ixs);
        validate_vector_passthrough(&data, &metas, OWN, &expectation())
    }

    #[test]
    fn passthrough_accepts_verify_plus_vote() {
        pt(&[embedded_self(), embedded_vote(pk(102))]).unwrap();
    }

    #[test]
    fn passthrough_rejects_bad_content_and_framing() {
        assert_eq!(
            code(pt(&[embedded_self(), embedded_vote(pk(66))])),
            err_code(ClearSigningError::VoteProposalMismatch)
        );
        assert_eq!(
            code(pt(&[embedded_self()])),
            err_code(ClearSigningError::MissingVoteInstruction)
        );
        assert_eq!(
            code(pt(&[embedded_vote(pk(102))])),
            err_code(ClearSigningError::EmbeddedSelfInstructionMissing)
        );
        let foreign = (pk(200), vec![], b"x".to_vec());
        assert_eq!(
            code(pt(&[embedded_self(), foreign, embedded_vote(pk(102))])),
            err_code(ClearSigningError::ForbiddenInstruction)
        );
        // A vote by someone other than the expected member.
        let mut other_member = embedded_vote(pk(102));
        other_member.1[1] = pk(66);
        assert_eq!(
            code(pt(&[embedded_self(), other_member])),
            err_code(ClearSigningError::VoteMemberMismatch)
        );

        let exp = expectation();
        let (data, metas) = passthrough(&[embedded_self(), embedded_vote(pk(102))]);
        let check = |d: &[u8], m: &[AccountMeta]| {
            code(validate_vector_passthrough(d, m, OWN, &exp))
        };
        let bad_driver = err_code(ClearSigningError::MalformedDriverInstruction);
        let malformed = err_code(ClearSigningError::MalformedEmbeddedInstructions);
        let trailing = err_code(ClearSigningError::EmbeddedTrailingBytes);
        // Not a Passthrough; a Passthrough of a different vector PDA.
        let mut advance = data.clone();
        advance[0] = 1;
        assert_eq!(check(&advance, &metas), bad_driver);
        let mut other_pda = metas.clone();
        other_pda[0].pubkey = pk(66);
        assert_eq!(check(&data, &other_pda), bad_driver);
        // Truncated data, missing accounts.
        assert_eq!(check(&data[..data.len() - 1], &metas), malformed);
        assert_eq!(check(&data, &metas[..metas.len() - 1]), malformed);
        // Extra data bytes / extra accounts left unconsumed.
        let mut longer = data.clone();
        longer.push(0);
        assert_eq!(check(&longer, &metas), trailing);
        let mut more = metas.clone();
        more.push(AccountMeta::new_readonly(pk(1), false));
        assert_eq!(check(&data, &more), trailing);
    }

    #[test]
    fn vector_siblings_must_be_advances() {
        let vector = pk(150);
        check_vector_sibling(&vector, &[1, 0xAA], &vector).unwrap();
        // Other programs are not the member's signer: unrestricted.
        check_vector_sibling(&pk(200), &[4], &vector).unwrap();
        for data in [&[4u8, 1][..], &[0], &[]] {
            assert_eq!(
                code(check_vector_sibling(&vector, data, &vector)),
                err_code(ClearSigningError::ForbiddenDriverInstruction)
            );
        }
    }

    #[test]
    fn cpi_error_codes_are_appended() {
        assert_eq!(err_code(ClearSigningError::ProgramHashMismatch), 6047);
        assert_eq!(err_code(ClearSigningError::NotInvokedViaCpi), 6048);
        assert_eq!(err_code(ClearSigningError::ForbiddenDriverInstruction), 6055);
    }
}
