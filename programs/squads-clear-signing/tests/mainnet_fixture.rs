//! Decodes a real mainnet Squads v4 `VaultTransaction` account (fetched from
//! `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf`) to prove the mirrored layout
//! matches the deployed program, then runs the full "honest wallet" validation
//! path against it.

use std::str::FromStr;

use anchor_lang::prelude::Pubkey;
use squads_clear_signing::squads::{derive_transaction_pda, VaultTransaction};
use squads_clear_signing::validation::{validate_instructions, AccountKeys};
use squads_clear_signing::{ExpectedAccountMeta, ExpectedInstruction};

const FIXTURE: &[u8] = include_bytes!("fixtures/vault_transaction.bin");
const FIXTURE_ADDRESS: &str = include_str!("fixtures/vault_transaction.address");

#[test]
fn decodes_real_mainnet_vault_transaction() {
    let tx = VaultTransaction::deserialize_checked(FIXTURE)
        .expect("mirrored layout must decode a real mainnet VaultTransaction");

    // The account's own (multisig, index) must re-derive its address —
    // this exercises the exact PDA binding the program relies on.
    let expected_address = Pubkey::from_str(FIXTURE_ADDRESS.trim()).unwrap();
    assert_eq!(derive_transaction_pda(&tx.multisig, tx.index), expected_address);

    // Basic sanity on the decoded message.
    let message = &tx.message;
    assert!(!message.account_keys.is_empty());
    assert!(!message.instructions.is_empty());
    assert!(usize::from(message.num_signers) <= message.account_keys.len());

    // Simulate the honest wallet: expand the compiled message into the
    // ExpectedInstruction list a device would be shown, then validate.
    // (Fixture has no address table lookups; skip key resolution via ALTs.)
    assert!(
        message.address_table_lookups.is_empty(),
        "fixture unexpectedly uses lookup tables; update the test to fetch them"
    );
    let keys = AccountKeys::resolve(message, &[]).unwrap();
    let expected: Vec<ExpectedInstruction> = message
        .instructions
        .iter()
        .map(|ix| ExpectedInstruction {
            program_id: *keys.get(usize::from(ix.program_id_index)).unwrap(),
            accounts: ix
                .account_indexes
                .iter()
                .map(|&i| {
                    let i = usize::from(i);
                    ExpectedAccountMeta {
                        pubkey: *keys.get(i).unwrap(),
                        is_signer: keys.is_signer(i),
                        is_writable: keys.is_writable(i),
                    }
                })
                .collect(),
            data: ix.data.clone(),
        })
        .collect();
    validate_instructions(message, &keys, &expected).unwrap();

    // And a tampered view must fail: flip one byte of one instruction's data.
    let mut tampered = expected;
    tampered[0].data = {
        let mut d = tampered[0].data.clone();
        if d.is_empty() { d.push(1) } else { d[0] ^= 1 }
        d
    };
    assert!(validate_instructions(message, &keys, &tampered).is_err());
}
