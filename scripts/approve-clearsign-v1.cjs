#!/usr/bin/env node
/**
 * Clear-signed Squads approval built as a **version-1 transaction** (@solana/kit),
 * which raises the size limit from 1232 to 4096 bytes so a larger bundle's
 * verify_proposal payload fits alongside the vote:
 *
 *   v1 tx = [ verify_buffer_hash(buffer, sha256)?,  verify_proposal(bundle),  proposal_approve ]
 *
 * v1 folds the compute-unit limit and loaded-accounts-data-size into the message
 * config (no ComputeBudget instruction), so the instructions the sysvar sees are
 * exactly the two clear-signing instructions plus the vote.
 *
 * Instructions are built with anchor / @sqds/multisig (web3.js) and converted to
 * kit instructions; reads use a web3.js Connection. Signing/sending is kit (v1).
 *
 * Env: RPC_URL, WALLET, MULTISIG, TX_INDEX (default 1), BUFFER, SO_FILE,
 *      TAMPER = none|hash|data, CU_LIMIT (default 400_000),
 *      LOADED_DATA (default 10_000_000).
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Connection, PublicKey, Keypair, TransactionInstruction, SYSVAR_INSTRUCTIONS_PUBKEY } = require("@solana/web3.js");
const multisig = require("@sqds/multisig");
const anchor = require("@anchor-lang/core");
const kit = require("@solana/kit");

const ROOT = path.join(__dirname, "..");
const IDL = JSON.parse(fs.readFileSync(path.join(ROOT, "idl", "squads_clear_signing.json")));
const ok = (m) => console.log(`\x1b[32m✔\x1b[0m ${m}`);
const info = (m) => console.log(`  ${m}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const req = (n) => { const v = process.env[n]; if (!v) throw new Error(`missing env ${n}`); return v; };
const trim = (b) => { let e = b.length; while (e > 0 && b[e - 1] === 0) e--; return b.subarray(0, e); };

// verify_proposal discriminator = sha256("global:verify_proposal")[..8].
const VERIFY_PROPOSAL_DISC = Buffer.from([54, 140, 57, 70, 243, 157, 30, 124]);
const ACTION_INDEX = { approve: 0, reject: 1, cancel: 2, cancelV2: 3 };

/**
 * Hand-encode VerifyProposalArgs (borsh) — Anchor's client coder caps
 * instruction data at a 1000-byte buffer, which a multi-instruction bundle's
 * expected content overruns. Layout mirrors the Rust structs exactly.
 */
function encodeVerifyProposalIx(programId, args, keys) {
  const u8 = (n) => Buffer.from([n]);
  const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
  const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
  const pk = (p) => p.toBuffer();
  const vecU8 = (buf) => Buffer.concat([u32(buf.length), buf]);

  const head = Buffer.concat([
    pk(args.multisig), u64(args.transactionIndex), u8(args.vaultIndex),
    u8(args.numEphemeralSigners), pk(args.member), u8(args.actionIndex),
  ]);
  const ixBufs = args.instructions.map((ix) => {
    const accts = Buffer.concat(ix.accounts.map((a) =>
      Buffer.concat([pk(a.pubkey), u8(a.isSigner ? 1 : 0), u8(a.isWritable ? 1 : 0)])));
    return Buffer.concat([pk(ix.programId), u32(ix.accounts.length), accts, vecU8(Buffer.from(ix.data))]);
  });
  const data = Buffer.concat([VERIFY_PROPOSAL_DISC, head, u32(ixBufs.length), ...ixBufs]);
  return new TransactionInstruction({ programId, keys, data });
}

/** web3.js TransactionInstruction -> kit instruction */
function toKitIx(ix) {
  const R = kit.AccountRole;
  return {
    programAddress: kit.address(ix.programId.toBase58()),
    accounts: ix.keys.map((k) => ({
      address: kit.address(k.pubkey.toBase58()),
      role: k.isSigner
        ? (k.isWritable ? R.WRITABLE_SIGNER : R.READONLY_SIGNER)
        : (k.isWritable ? R.WRITABLE : R.READONLY),
    })),
    data: new Uint8Array(ix.data),
  };
}

function buildExpected(message) {
  if (message.addressTableLookups.length > 0) {
    throw new Error("bundle uses ALTs; extend script to pass them as remaining accounts");
  }
  const keys = message.accountKeys;
  const nSig = message.numSigners;
  const isSigner = (i) => i < nSig;
  const isWritable = (i) =>
    i < message.numWritableSigners || (i >= nSig && i - nSig < message.numWritableNonSigners);
  return message.instructions.map((ix) => ({
    programId: keys[ix.programIdIndex],
    accounts: Array.from(ix.accountIndexes).map((i) => ({
      pubkey: keys[i], isSigner: isSigner(i), isWritable: isWritable(i),
    })),
    data: Buffer.from(ix.data),
  }));
}

async function main() {
  const URL = process.env.RPC_URL || "http://127.0.0.1:8899";
  const connection = new Connection(URL, "confirmed");
  const secret = Uint8Array.from(JSON.parse(fs.readFileSync(req("WALLET"))));
  const walletKp = Keypair.fromSecretKey(secret);
  const multisigPda = new PublicKey(req("MULTISIG"));
  const transactionIndex = BigInt(process.env.TX_INDEX || "1");
  const tamper = process.env.TAMPER || "none";
  const expectFail = tamper !== "none";

  const provider = new anchor.AnchorProvider(connection, new anchor.Wallet(walletKp), { commitment: "confirmed" });
  const program = new anchor.Program(IDL, provider);

  const [transactionPda] = multisig.getTransactionPda({ multisigPda, index: transactionIndex });
  const [proposalPda] = multisig.getProposalPda({ multisigPda, transactionIndex });
  const vaultTx = await multisig.accounts.VaultTransaction.fromAccountAddress(connection, transactionPda);
  const expected = buildExpected(vaultTx.message);
  info(`proposal ${proposalPda.toBase58()} — bundle has ${expected.length} instruction(s):`);
  expected.forEach((ix, i) => info(`  #${i} ${ix.programId.toBase58()} (${ix.data.length} data bytes, ${ix.accounts.length} accts)`));

  // --- build the web3.js instructions ---
  const web3Ixs = [];
  if (process.env.BUFFER) {
    const buffer = new PublicKey(process.env.BUFFER);
    const so = fs.readFileSync(req("SO_FILE"));
    let expectedHash = crypto.createHash("sha256").update(trim(so)).digest("hex");
    if (tamper === "hash") { // flip one hex char -> valid hex, wrong digest
      const r = expectedHash[5] === "f" ? "e" : "f";
      expectedHash = expectedHash.slice(0, 5) + r + expectedHash.slice(6);
    }
    web3Ixs.push(await program.methods
      .verifyBufferHash({ buffer, expectedHash })
      .accounts({ buffer }).instruction());
    info(`verify_buffer_hash: buffer ${buffer.toBase58()} sha256 ${expectedHash}${tamper === "hash" ? " (TAMPERED)" : ""}`);
  }
  if (tamper === "data") { expected[0].data = Buffer.from(expected[0].data); expected[0].data[0] ^= 0xff; info("expected instruction data TAMPERED"); }

  // verify_proposal: hand-encoded (Anchor's coder overruns its 1000-byte buffer
  // for multi-instruction bundles). Account order matches the Accounts struct:
  // transaction (ro), instructions_sysvar (ro), then ALT remaining accounts (none).
  web3Ixs.push(encodeVerifyProposalIx(
    new PublicKey(IDL.address),
    {
      multisig: multisigPda,
      transactionIndex,
      vaultIndex: vaultTx.vaultIndex,
      numEphemeralSigners: vaultTx.ephemeralSignerBumps.length,
      member: walletKp.publicKey,
      actionIndex: ACTION_INDEX.approve,
      instructions: expected,
    },
    [
      { pubkey: transactionPda, isSigner: false, isWritable: false },
      { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
    ],
  ));
  web3Ixs.push(multisig.instructions.proposalApprove({ multisigPda, transactionIndex, member: walletKp.publicKey }));

  // --- assemble the v1 transaction with kit ---
  const rpc = kit.createSolanaRpc(URL);
  const signer = await kit.createKeyPairSignerFromBytes(secret);
  const { value: latest } = await rpc.getLatestBlockhash({ commitment: "confirmed" }).send();
  // SHA-256 via syscall is cheap, so a modest limit suffices (this also fits
  // surfpool's default, which ignores the v1 config CU limit). Loaded-data must
  // still cover the ~180KB clear-signing program + Squads program.
  const CU = Number(process.env.CU_LIMIT || 400_000);
  const LOADED = Number(process.env.LOADED_DATA || 10_000_000);

  let message = kit.pipe(
    kit.createTransactionMessage({ version: 1 }),
    (m) => kit.setTransactionMessageFeePayerSigner(signer, m),
    (m) => kit.setTransactionMessageLifetimeUsingBlockhash(latest, m),
    (m) => kit.setTransactionMessageComputeUnitLimit(CU, m),
    (m) => kit.setTransactionMessageLoadedAccountsDataSizeLimit(LOADED, m),
  );
  for (const ix of web3Ixs) message = kit.appendTransactionMessageInstruction(toKitIx(ix), message);

  const signed = await kit.signTransactionMessageWithSigners(message);
  const wire = kit.getBase64EncodedWireTransaction(signed);
  const sizeBytes = Buffer.from(wire, "base64").length;
  const sig = kit.getSignatureFromTransaction(signed);
  info(`v1 transaction size: ${sizeBytes} bytes (legacy/v0 limit 1232, v1 limit 4096)`);

  const approvedBefore = (await multisig.accounts.Proposal.fromAccountAddress(connection, proposalPda)).approved.length;

  // Always skip preflight so both honest and tampered outcomes land on-chain and
  // their logs are fetchable (kit's preflight-reject throws before logs are available).
  let err = null;
  try {
    await rpc.sendTransaction(wire, { encoding: "base64", skipPreflight: true }).send();
  } catch (e) {
    // A landed, deterministically-failing tx can still reject at send on some RPCs;
    // fall through to status polling either way.
    if (!/already|preflight|simulation/i.test(String(e.message))) { /* keep going */ }
  }
  for (let i = 0; i < 40; i++) {
    const { value } = await rpc.getSignatureStatuses([sig]).send();
    const st = value[0];
    if (st && (st.confirmationStatus === "confirmed" || st.confirmationStatus === "finalized")) { err = st.err; break; }
    if (i === 39) throw new Error(`timed out confirming ${sig}`);
    await sleep(2000);
  }

  const proposal = await multisig.accounts.Proposal.fromAccountAddress(connection, proposalPda);
  const J = (o) => JSON.stringify(o, (k, v) => (typeof v === "bigint" ? v.toString() : v));

  if (expectFail) {
    if (!err) throw new Error(`TAMPERED (${tamper}) v1 approval unexpectedly SUCCEEDED: ${sig}`);
    info(`on-chain failure recorded: ${sig}`);
    info(`err: ${J(err)}`);
    try {
      const tx = await rpc.getTransaction(sig, { maxSupportedTransactionVersion: 1, encoding: "json", commitment: "confirmed" }).send();
      (tx?.meta?.logMessages || []).filter((l) => /Error|mismatch/.test(l)).forEach((l) => info(l));
    } catch (_) { /* logs optional */ }
    if (proposal.approved.length !== approvedBefore) throw new Error("vote recorded despite failure!");
    ok(`tampered (${tamper}) v1 approval failed on-chain; no vote recorded`);
  } else {
    if (err) {
      let logs = [];
      try { const tx = await rpc.getTransaction(sig, { maxSupportedTransactionVersion: 1, encoding: "json", commitment: "confirmed" }).send(); logs = tx?.meta?.logMessages || []; } catch (_) {}
      throw new Error(`honest v1 approval failed: ${J(err)} (${sig})\n${logs.join("\n")}`);
    }
    if (!proposal.approved.some((k) => k.equals(walletKp.publicKey))) throw new Error("v1 tx landed but vote not recorded");
    ok(`clear-signed v1 approval landed: ${sig}`);
    ok(`proposal approved by: ${walletKp.publicKey.toBase58()}`);
  }
}

main().catch((e) => { console.error(`\x1b[31m✗\x1b[0m ${e.message || e}`); if (process.env.DEBUG) console.error(e.stack); process.exit(1); });
