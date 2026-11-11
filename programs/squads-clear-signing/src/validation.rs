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
    let vote_discriminator = expectation.action.discriminator();
    let mut votes: usize = 0;

    for (i, ix) in top_level.iter().enumerate() {
        if ix.program_id == expectation.self_program
            || ix.program_id == COMPUTE_BUDGET_PROGRAM_ID
        {
            continue;
        }
        if ix.program_id == SQUADS_PROGRAM_ID {
            if ix.data.len() < 8 || ix.data[..8] != vote_discriminator {
                msg!("ix {}: unexpected Squads instruction (wrong discriminator)", i);
                return err!(ClearSigningError::UnexpectedSquadsInstruction);
            }
            // ProposalVote accounts: 0 = multisig, 1 = member (signer), 2 = proposal.
            if ix.accounts.len() < 3 {
                return err!(ClearSigningError::MalformedVoteInstruction);
            }
            if ix.accounts[0].pubkey != expectation.multisig {
                msg!("ix {}: vote multisig {} != expected", i, ix.accounts[0].pubkey);
                return err!(ClearSigningError::VoteMultisigMismatch);
            }
            if ix.accounts[1].pubkey != expectation.member {
                msg!("ix {}: vote member {} != expected", i, ix.accounts[1].pubkey);
                return err!(ClearSigningError::VoteMemberMismatch);
            }
            if !ix.accounts[1].is_signer {
                return err!(ClearSigningError::VoteMemberNotSigner);
            }
            if ix.accounts[2].pubkey != expectation.proposal {
                msg!("ix {}: vote proposal {} != expected", i, ix.accounts[2].pubkey);
                return err!(ClearSigningError::VoteProposalMismatch);
            }
            votes += 1;
            continue;
        }
        msg!("ix {}: forbidden program {}", i, ix.program_id);
        return err!(ClearSigningError::ForbiddenInstruction);
    }

    require!(votes >= 1, ClearSigningError::MissingVoteInstruction);
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
}
