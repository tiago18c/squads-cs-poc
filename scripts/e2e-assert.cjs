#!/usr/bin/env node
/**
 * On-chain checks for `assert_account_hash` and `assert_program_revision`
 * against a live cluster (surfpool or devnet). Needs no multisig: both
 * instructions are standalone assertions, so each case is a one-instruction
 * transaction sent with skipPreflight (failures are recorded on-chain).
 *
 * Targets:
 *   - assert_account_hash on the clear-signing Program account itself
 *     (36 bytes, owned by the BPF upgradeable loader)
 *   - assert_program_revision on the clear-signing program, with the expected
 *     digest read from its ProgramData (== `solana-verify get-program-hash`),
 *     cross-checked against target/deploy/squads_clear_signing.so if present
 *
 * Env:
 *   RPC_URL  target cluster (default http://127.0.0.1:8899)
 *   WALLET   keypair path (default keys/e2e-wallet.json)
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bs58 = (() => { const m = require("bs58"); return m.default ?? m; })();
const { Connection, Keypair, PublicKey, Transaction, LAMPORTS_PER_SOL } = require("@solana/web3.js");
const anchor = require("@anchor-lang/core");

const ROOT = path.join(__dirname, "..");
const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8899";
const WALLET_PATH = process.env.WALLET || path.join(ROOT, "keys", "e2e-wallet.json");
const IDL = JSON.parse(fs.readFileSync(path.join(ROOT, "idl", "squads_clear_signing.json")));
const SO_PATH = path.join(ROOT, "target", "deploy", "squads_clear_signing.so");
const IS_LOCAL = /127\.0\.0\.1|localhost/.test(RPC_URL);
const PACE_MS = IS_LOCAL ? 0 : 3000;

const LOADER_V3 = new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111");
const SQUADS_V4 = new PublicKey("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf");
const SYSTEM = new PublicKey("11111111111111111111111111111111");
const PROGRAMDATA_METADATA_SIZE = 45;

const ok = (m) => console.log(`\x1b[32m✔\x1b[0m ${m}`);
const step = (m) => console.log(`\n\x1b[36m▶ ${m}\x1b[0m`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
function trim(bytes) {
  let end = bytes.length;
  while (end > 0 && bytes[end - 1] === 0) end--;
  return bytes.subarray(0, end);
}

async function sendTx(connection, instructions, signers) {
  const { blockhash } = await connection.getLatestBlockhash("confirmed");
  const tx = new Transaction().add(...instructions);
  tx.recentBlockhash = blockhash;
  tx.feePayer = signers[0].publicKey;
  tx.sign(...signers);
  const sig = bs58.encode(tx.signature);
  await connection.sendRawTransaction(tx.serialize(), { skipPreflight: true, maxRetries: 5 });
  for (let i = 0; i < 40; i++) {
    const st = (await connection.getSignatureStatuses([sig])).value[0];
    if (st && (st.confirmationStatus === "confirmed" || st.confirmationStatus === "finalized")) {
      return { sig, err: st.err };
    }
    await sleep(1500);
  }
  throw new Error(`timed out confirming ${sig}`);
}

async function main() {
  const connection = new Connection(RPC_URL, "confirmed");
  const wallet = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(WALLET_PATH))));
  console.log(`cluster: ${RPC_URL}`);
  console.log(`wallet:  ${wallet.publicKey.toBase58()}`);
  if ((await connection.getBalance(wallet.publicKey)) < 0.05 * LAMPORTS_PER_SOL) {
    if (!IS_LOCAL) throw new Error("wallet needs funds");
    const sig = await connection.requestAirdrop(wallet.publicKey, 5 * LAMPORTS_PER_SOL);
    await connection.confirmTransaction(sig, "confirmed");
  }

  const provider = new anchor.AnchorProvider(connection, new anchor.Wallet(wallet), { commitment: "confirmed" });
  const program = new anchor.Program(IDL, provider);
  const programId = program.programId;
  const errorCode = (name) => IDL.errors.find((e) => e.name === name).code;

  // --- chain truth -----------------------------------------------------------
  const programInfo = await connection.getAccountInfo(programId);
  if (!programInfo) throw new Error(`program ${programId} not deployed — run scripts/run-e2e.sh first`);
  const programData = new PublicKey(programInfo.data.subarray(4, 36));
  const pdInfo = await connection.getAccountInfo(programData);
  const programHash = sha256(trim(pdInfo.data.subarray(PROGRAMDATA_METADATA_SIZE)));
  const programAccountHash = sha256(programInfo.data);
  ok(`program ${programId.toBase58()} -> programdata ${programData.toBase58()}`);
  ok(`program hash (solana-verify get-program-hash): ${programHash}`);
  if (fs.existsSync(SO_PATH)) {
    const local = sha256(trim(fs.readFileSync(SO_PATH)));
    console.log(`  local .so hash: ${local} ${local === programHash ? "(matches deployed)" : "(differs from deployed!)"}`);
  }
  const squadsInfo = await connection.getAccountInfo(SQUADS_V4);
  const squadsProgramData = squadsInfo ? new PublicKey(squadsInfo.data.subarray(4, 36)) : null;

  const accountHashIx = (args, account = args.account) => program.methods
    .assertAccountHash(args).accounts({ account }).instruction();
  const revisionIx = (args, accts = {}) => program.methods
    .assertProgramRevision(args)
    .accounts({ program: accts.program ?? args.program, programData: accts.programData ?? programData })
    .instruction();
  const wrongHash = sha256(Buffer.from("not the build"));

  const cases = [
    // assert_account_hash
    { label: "account hash, owner = loader", ix: () => accountHashIx({ account: programId, owner: LOADER_V3, expectedHash: programAccountHash }) },
    { label: "account hash, owner = None", ix: () => accountHashIx({ account: programId, owner: null, expectedHash: programAccountHash }) },
    { label: "account hash, empty system account", ix: () => accountHashIx({ account: wallet.publicKey, owner: SYSTEM, expectedHash: sha256(Buffer.alloc(0)) }) },
    { label: "account hash, wrong owner", expect: "AccountOwnerMismatch", ix: () => accountHashIx({ account: programId, owner: SYSTEM, expectedHash: programAccountHash }) },
    { label: "account hash, wrong hash", expect: "AccountHashMismatch", ix: () => accountHashIx({ account: programId, owner: null, expectedHash: wrongHash }) },
    { label: "account hash, uppercase hex", expect: "InvalidHashFormat", ix: () => accountHashIx({ account: programId, owner: null, expectedHash: programAccountHash.toUpperCase() }) },
    { label: "account hash, args/account mismatch", expect: "AssertedAccountMismatch", ix: () => accountHashIx({ account: programId, owner: null, expectedHash: programAccountHash }, programData) },
    // assert_program_revision
    { label: "program revision, honest", ix: () => revisionIx({ program: programId, expectedHash: programHash }) },
    { label: "program revision, wrong hash", expect: "ProgramHashMismatch", ix: () => revisionIx({ program: programId, expectedHash: wrongHash }) },
    { label: "program revision, malformed hash", expect: "InvalidHashFormat", ix: () => revisionIx({ program: programId, expectedHash: programHash.slice(2) }) },
    { label: "program revision, args/program mismatch", expect: "ProgramKeyMismatch", ix: () => revisionIx({ program: programId, expectedHash: programHash }, { program: SQUADS_V4 }) },
    { label: "program revision, programdata passed as program", expect: "NotAProgram", ix: () => revisionIx({ program: programData, expectedHash: programHash }) },
    { label: "program revision, non-loader program account", expect: "InvalidProgramOwner", ix: () => revisionIx({ program: wallet.publicKey, expectedHash: programHash }) },
    ...(squadsProgramData ? [{
      label: "program revision, another program's programdata", expect: "ProgramDataAddressMismatch",
      ix: () => revisionIx({ program: programId, expectedHash: programHash }, { programData: squadsProgramData }),
    }] : []),
  ];

  for (const c of cases) {
    step(`${c.label} — must ${c.expect ? `fail with ${c.expect}` : "succeed"}`);
    const res = await sendTx(connection, [await c.ix()], [wallet]);
    if (!c.expect) {
      if (res.err) throw new Error(`expected success, got ${JSON.stringify(res.err)} (${res.sig})`);
      ok(`succeeded: ${res.sig}`);
    } else {
      const code = res.err?.InstructionError?.[1]?.Custom;
      if (code !== errorCode(c.expect)) {
        throw new Error(`expected ${c.expect} (${errorCode(c.expect)}), got ${JSON.stringify(res.err)} (${res.sig})`);
      }
      ok(`rejected on-chain with ${c.expect} (${code}): ${res.sig}`);
    }
    await sleep(PACE_MS);
  }

  console.log(`\n\x1b[32mE2E-ASSERT PASSED\x1b[0m — ${cases.length} cases.`);
}

main().catch((e) => { console.error("\n\x1b[31mE2E-ASSERT FAILED:\x1b[0m", e); process.exit(1); });
