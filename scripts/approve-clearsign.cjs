#!/usr/bin/env node
/**
 * Clear-signed Squads approval, optionally with buffer-hash verification:
 *
 *   tx = [ verify_buffer_hash(buffer, sha256-trimmed)   (when BUFFER is set)
 *          verify_proposal(<expected content from chain>),
 *          proposal_approve ]
 *
 * Env:
 *   RPC_URL     cluster (default http://127.0.0.1:8899)
 *   WALLET      member keypair path (required)
 *   MULTISIG    multisig PDA (required)
 *   TX_INDEX    proposal / transaction index (default 1)
 *   BUFFER      loader-v3 buffer to hash-check (optional)
 *   SO_FILE     local .so the buffer must match (required with BUFFER)
 *   TAMPER      none (default) | hash | data — corrupt one byte and EXPECT the
 *               transaction to fail on-chain with no vote recorded
 *
 * Exit 0 = observed behavior matched the expectation (honest approve landed,
 * or tampered approve failed with no vote). Anything else exits 1.
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bs58 = (() => { const m = require("bs58"); return m.default ?? m; })();
const {
  Connection, Keypair, PublicKey, Transaction, ComputeBudgetProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
} = require("@solana/web3.js");
const multisig = require("@sqds/multisig");
const anchor = require("@anchor-lang/core");

const ROOT = path.join(__dirname, "..");
const IDL = JSON.parse(fs.readFileSync(path.join(ROOT, "idl", "squads_clear_signing.json")));

const ok = (m) => console.log(`\x1b[32m✔\x1b[0m ${m}`);
const info = (m) => console.log(`  ${m}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function req(name) {
  const v = process.env[name];
  if (!v) throw new Error(`missing env ${name}`);
  return v;
}

function trim(bytes) {
  let end = bytes.length;
  while (end > 0 && bytes[end - 1] === 0) end--;
  return bytes.subarray(0, end);
}

async function withRetry(fn, label, tries = 8) {
  for (let i = 0; ; i++) {
    try { return await fn(); }
    catch (e) {
      if (i >= tries - 1) throw e;
      const wait = 2500 * (i + 1);
      info(`(retrying ${label} in ${wait / 1000}s: ${String(e.message).slice(0, 90)})`);
      await sleep(wait);
    }
  }
}

async function sendTx(connection, instructions, signers, { skipPreflight = false } = {}) {
  // Sign fresh each attempt so a genuine simulation failure surfaces its logs
  // instead of decaying into "Blockhash not found" after the hash expires.
  let sig;
  await withRetry(async () => {
    const { blockhash } = await connection.getLatestBlockhash("confirmed");
    const tx = new Transaction().add(...instructions);
    tx.recentBlockhash = blockhash;
    tx.feePayer = signers[0].publicKey;
    tx.sign(...signers);
    sig = bs58.encode(tx.signature);
    try { await connection.sendRawTransaction(tx.serialize(), { skipPreflight, maxRetries: 5 }); }
    catch (e) {
      if (/already.*processed/i.test(String(e.message))) return;
      // A deterministic on-chain failure (our validation aborting) is the
      // EXPECTED outcome for tampered runs — don't retry it as if transient.
      if (skipPreflight) return;
      throw e;
    }
  }, "send");
  for (let i = 0; i < 40; i++) {
    const st = (await withRetry(() => connection.getSignatureStatuses([sig]), "status")).value[0];
    if (st && (st.confirmationStatus === "confirmed" || st.confirmationStatus === "finalized")) {
      return { sig, err: st.err };
    }
    await sleep(2000);
  }
  throw new Error(`timed out confirming ${sig}`);
}

function buildExpected(message) {
  if (message.addressTableLookups.length > 0) {
    throw new Error("bundle uses address lookup tables; extend this script to pass them as remaining accounts");
  }
  const keys = message.accountKeys;
  const numSigners = message.numSigners;
  const isSigner = (i) => i < numSigners;
  const isWritable = (i) =>
    i < message.numWritableSigners ||
    (i >= numSigners && i - numSigners < message.numWritableNonSigners);
  return message.instructions.map((ix) => ({
    programId: keys[ix.programIdIndex],
    accounts: Array.from(ix.accountIndexes).map((i) => ({
      pubkey: keys[i], isSigner: isSigner(i), isWritable: isWritable(i),
    })),
    data: Buffer.from(ix.data),
  }));
}

async function main() {
  const connection = new Connection(process.env.RPC_URL || "http://127.0.0.1:8899", "confirmed");
  const wallet = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(req("WALLET")))));
  const multisigPda = new PublicKey(req("MULTISIG"));
  const transactionIndex = BigInt(process.env.TX_INDEX || "1");
  const tamper = process.env.TAMPER || "none";
  const expectFail = tamper !== "none";

  const provider = new anchor.AnchorProvider(connection, new anchor.Wallet(wallet), { commitment: "confirmed" });
  const program = new anchor.Program(IDL, provider);

  const [transactionPda] = multisig.getTransactionPda({ multisigPda, index: transactionIndex });
  const [proposalPda] = multisig.getProposalPda({ multisigPda, transactionIndex });
  const vaultTx = await withRetry(
    () => multisig.accounts.VaultTransaction.fromAccountAddress(connection, transactionPda),
    "fetch VaultTransaction",
  );
  const expected = buildExpected(vaultTx.message);
  info(`proposal ${proposalPda.toBase58()} — bundle has ${expected.length} instruction(s):`);
  expected.forEach((ix, i) => info(`  #${i} program ${ix.programId.toBase58()} (${ix.data.length} data bytes, ${ix.accounts.length} accounts)`));

  const instructions = [];

  // Raise the compute limit: hashing a full program ELF with brine's software
  // SHA-512 costs well over the 200k default. ComputeBudget instructions are
  // explicitly allowed by verify_proposal's transaction-shape check.
  if (process.env.BUFFER) {
    instructions.push(ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }));
  }

  // Optional leading verify_buffer_hash.
  if (process.env.BUFFER) {
    const buffer = new PublicKey(process.env.BUFFER);
    const so = fs.readFileSync(req("SO_FILE"));
    let expectedHash = crypto.createHash("sha256").update(trim(so)).digest("hex");
    if (tamper === "hash") { // flip one hex char -> valid hex, wrong digest
      const r = expectedHash[5] === "f" ? "e" : "f";
      expectedHash = expectedHash.slice(0, 5) + r + expectedHash.slice(6);
    }
    instructions.push(await program.methods
      .verifyBufferHash({ buffer, expectedHash })
      .accounts({ buffer })
      .instruction());
    info(`buffer ${buffer.toBase58()} expected sha256: ${expectedHash}${tamper === "hash" ? " (TAMPERED)" : ""}`);
  }

  if (tamper === "data") {
    expected[0].data = Buffer.from(expected[0].data);
    expected[0].data[0] ^= 0xff;
    info("expected instruction data TAMPERED (first byte flipped)");
  }

  instructions.push(await program.methods
    .verifyProposal({
      multisig: multisigPda,
      transactionIndex: new anchor.BN(transactionIndex.toString()),
      vaultIndex: vaultTx.vaultIndex,
      numEphemeralSigners: vaultTx.ephemeralSignerBumps.length,
      member: wallet.publicKey,
      action: { approve: {} },
      instructions: expected,
    })
    .accounts({ transaction: transactionPda, instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY })
    .instruction());

  instructions.push(multisig.instructions.proposalApprove({
    multisigPda, transactionIndex, member: wallet.publicKey,
  }));

  const approvedBefore = (await withRetry(
    () => multisig.accounts.Proposal.fromAccountAddress(connection, proposalPda), "fetch Proposal",
  )).approved.length;

  const { sig, err } = await sendTx(connection, instructions, [wallet], { skipPreflight: expectFail });

  const proposal = await withRetry(
    () => multisig.accounts.Proposal.fromAccountAddress(connection, proposalPda), "fetch Proposal",
  );

  if (expectFail) {
    if (!err) throw new Error(`TAMPERED (${tamper}) approval unexpectedly SUCCEEDED: ${sig}`);
    info(`on-chain failure recorded: ${sig}`);
    info(`err: ${JSON.stringify(err)}`);
    const rec = await withRetry(
      () => connection.getTransaction(sig, { maxSupportedTransactionVersion: 0, commitment: "confirmed" }),
      "fetch failed tx",
    );
    (rec?.meta?.logMessages || [])
      .filter((l) => /Error|mismatch/.test(l))
      .forEach((l) => info(l));
    if (proposal.approved.length !== approvedBefore) throw new Error("vote recorded despite failure!");
    ok(`tampered (${tamper}) approval failed on-chain; no vote recorded`);
  } else {
    if (err) throw new Error(`honest approval failed: ${JSON.stringify(err)} (${sig})`);
    if (!proposal.approved.some((k) => k.equals(wallet.publicKey))) {
      throw new Error("approval tx landed but the vote is not recorded");
    }
    ok(`clear-signed approval landed: ${sig}`);
    ok(`proposal approved by: ${wallet.publicKey.toBase58()}`);
  }
}

main().catch((e) => { console.error(`\x1b[31m✗\x1b[0m ${String(e.message || e)}`); process.exit(1); });
