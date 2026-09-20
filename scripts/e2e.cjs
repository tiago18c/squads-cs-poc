#!/usr/bin/env node
/**
 * End-to-end clear-signing scenario against a live cluster (surfpool or devnet).
 *
 * Flow:
 *   1. create a fresh Squads v4 multisig (threshold 1, our wallet as sole member)
 *   2. fund vault 0, create a vault transaction: system transfer vault -> wallet
 *   3. create + activate the proposal
 *   4. TAMPERED approval:  [verify_proposal(wrong lamports), proposal_approve] -> must FAIL on-chain
 *   5. HONEST approval:    [verify_proposal(chain truth),   proposal_approve] -> must succeed
 *   6. execute the vault transaction and confirm the transfer landed
 *
 * Env:
 *   RPC_URL          target cluster (default http://127.0.0.1:8899)
 *   WALLET           keypair path (default keys/e2e-wallet.json)
 *   RESUME_MULTISIG  skip steps 1-3 and run 4-6 against an existing multisig
 *   RESUME_TX_INDEX  transaction index to resume at (default 1)
 */
const fs = require("fs");
const path = require("path");
const bs58 = (() => { const m = require("bs58"); return m.default ?? m; })();
const {
  Connection, Keypair, PublicKey, SystemProgram, Transaction, TransactionMessage,
  VersionedTransaction, SYSVAR_INSTRUCTIONS_PUBKEY, LAMPORTS_PER_SOL,
} = require("@solana/web3.js");
const multisig = require("@sqds/multisig");
const anchor = require("@anchor-lang/core");

const ROOT = path.join(__dirname, "..");
const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8899";
const WALLET_PATH = process.env.WALLET || path.join(ROOT, "keys", "e2e-wallet.json");
const IDL = JSON.parse(fs.readFileSync(path.join(ROOT, "idl", "squads_clear_signing.json")));
const IS_LOCAL = /127\.0\.0\.1|localhost/.test(RPC_URL);
const PACE_MS = IS_LOCAL ? 0 : 4000; // be gentle with public rate-limited RPCs

const ok = (m) => console.log(`\x1b[32m✔\x1b[0m ${m}`);
const step = (m) => console.log(`\n\x1b[36m▶ ${m}\x1b[0m`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function loadKeypair(p) {
  return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(p))));
}

/** Retry any RPC-touching closure on transient errors (429s, timeouts). */
async function withRetry(fn, label, tries = 8) {
  for (let i = 0; ; i++) {
    try { return await fn(); }
    catch (e) {
      if (i >= tries - 1) throw e;
      const wait = 2500 * (i + 1);
      console.log(`  (retrying ${label} in ${wait / 1000}s: ${String(e.message).slice(0, 90)})`);
      await sleep(wait);
    }
  }
}

/** Send a legacy tx and confirm by POLLING signature status (no websockets —
 *  public devnet RPC throttles ws). Returns {sig, err}. */
async function sendTx(connection, instructions, signers, { skipPreflight = false } = {}) {
  const { blockhash } = await withRetry(() => connection.getLatestBlockhash("confirmed"), "getLatestBlockhash");
  const tx = new Transaction().add(...instructions);
  tx.recentBlockhash = blockhash;
  tx.feePayer = signers[0].publicKey;
  tx.sign(...signers);
  const sig = bs58.encode(tx.signature);
  await withRetry(async () => {
    try {
      await connection.sendRawTransaction(tx.serialize(), { skipPreflight, maxRetries: 5 });
    } catch (e) {
      if (/already.*processed/i.test(String(e.message))) return; // resend of a landed tx
      throw e;
    }
  }, "sendTransaction");
  for (let i = 0; i < 40; i++) {
    const st = (await withRetry(
      () => connection.getSignatureStatuses([sig]), "getSignatureStatuses",
    )).value[0];
    if (st && (st.confirmationStatus === "confirmed" || st.confirmationStatus === "finalized")) {
      return { sig, err: st.err };
    }
    await sleep(2000);
  }
  throw new Error(`timed out confirming ${sig}`);
}

/** Expand the on-chain compiled message into ExpectedInstruction[], exactly
 *  like the program resolves it (static keys only; no ALTs in this scenario). */
function buildExpected(message) {
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
  const connection = new Connection(RPC_URL, "confirmed");
  const wallet = loadKeypair(WALLET_PATH);
  console.log(`cluster: ${RPC_URL}`);
  console.log(`wallet:  ${wallet.publicKey.toBase58()}`);

  // --- preflight: balance & program presence -------------------------------
  let balance = await withRetry(() => connection.getBalance(wallet.publicKey), "getBalance");
  if (balance < 0.5 * LAMPORTS_PER_SOL) {
    if (IS_LOCAL) {
      step("airdropping 20 SOL (local cluster)");
      const sig = await connection.requestAirdrop(wallet.publicKey, 20 * LAMPORTS_PER_SOL);
      await connection.confirmTransaction(sig, "confirmed");
      balance = await connection.getBalance(wallet.publicKey);
    } else {
      throw new Error(`wallet has ${balance / LAMPORTS_PER_SOL} SOL — fund it first`);
    }
  }
  console.log(`balance: ${balance / LAMPORTS_PER_SOL} SOL`);

  const programId = new PublicKey(IDL.address);
  if (!(await withRetry(() => connection.getAccountInfo(programId), "getProgram"))) {
    throw new Error(`clear-signing program ${programId} not deployed on this cluster — run scripts/run-e2e.sh, which deploys it`);
  }
  ok(`squads_clear_signing deployed at ${programId.toBase58()}`);

  const provider = new anchor.AnchorProvider(connection, new anchor.Wallet(wallet), { commitment: "confirmed" });
  const program = new anchor.Program(IDL, provider);

  let multisigPda;
  let transactionIndex;
  if (process.env.RESUME_MULTISIG) {
    multisigPda = new PublicKey(process.env.RESUME_MULTISIG);
    transactionIndex = BigInt(process.env.RESUME_TX_INDEX || "1");
    step(`RESUMING at multisig ${multisigPda.toBase58()}, transaction index ${transactionIndex}`);
  } else {
    // --- 1. create the multisig --------------------------------------------
    step("creating Squads v4 multisig (threshold 1)");
    const createKey = Keypair.generate();
    [multisigPda] = multisig.getMultisigPda({ createKey: createKey.publicKey });
    const [programConfigPda] = multisig.getProgramConfigPda({});
    const programConfig = await withRetry(
      () => multisig.accounts.ProgramConfig.fromAccountAddress(connection, programConfigPda),
      "fetch ProgramConfig",
    );
    const createIx = multisig.instructions.multisigCreateV2({
      createKey: createKey.publicKey,
      creator: wallet.publicKey,
      multisigPda,
      configAuthority: null,
      timeLock: 0,
      members: [{ key: wallet.publicKey, permissions: multisig.types.Permissions.all() }],
      threshold: 1,
      treasury: programConfig.treasury,
      rentCollector: null,
    });
    const created = await sendTx(connection, [createIx], [wallet, createKey]);
    if (created.err) throw new Error(`multisig create failed: ${JSON.stringify(created.err)}`);
    ok(`multisig: ${multisigPda.toBase58()}`);
    await sleep(PACE_MS);

    // --- 2. fund vault, create the vault transaction -----------------------
    transactionIndex = 1n;
    const [vaultPda] = multisig.getVaultPda({ multisigPda, index: 0 });
    step(`funding vault 0 (${vaultPda.toBase58()}) with 0.2 SOL`);
    const funded = await sendTx(connection, [SystemProgram.transfer({
      fromPubkey: wallet.publicKey, toPubkey: vaultPda, lamports: 0.2 * LAMPORTS_PER_SOL,
    })], [wallet]);
    if (funded.err) throw new Error(`vault funding failed: ${JSON.stringify(funded.err)}`);
    await sleep(PACE_MS);

    step("creating vault transaction: transfer 0.001 SOL vault -> wallet, plus proposal");
    const { blockhash } = await withRetry(() => connection.getLatestBlockhash(), "getLatestBlockhash");
    const innerMessage = new TransactionMessage({
      payerKey: vaultPda,
      recentBlockhash: blockhash,
      instructions: [SystemProgram.transfer({
        fromPubkey: vaultPda, toPubkey: wallet.publicKey, lamports: 0.001 * LAMPORTS_PER_SOL,
      })],
    });
    const txCreateIx = multisig.instructions.vaultTransactionCreate({
      multisigPda, transactionIndex, creator: wallet.publicKey,
      vaultIndex: 0, ephemeralSigners: 0, transactionMessage: innerMessage,
    });
    const proposalIx = multisig.instructions.proposalCreate({
      multisigPda, transactionIndex, creator: wallet.publicKey,
    });
    const made = await sendTx(connection, [txCreateIx, proposalIx], [wallet]);
    if (made.err) throw new Error(`vault tx create failed: ${JSON.stringify(made.err)}`);
    await sleep(PACE_MS);
  }

  const [transactionPda] = multisig.getTransactionPda({ multisigPda, index: transactionIndex });
  const [proposalPda] = multisig.getProposalPda({ multisigPda, transactionIndex });
  ok(`vault transaction: ${transactionPda.toBase58()}`);
  ok(`proposal:          ${proposalPda.toBase58()}`);

  // --- 3. build the verify instruction from CHAIN truth --------------------
  step("reading VaultTransaction back and building expected instruction list");
  const vaultTx = await withRetry(
    () => multisig.accounts.VaultTransaction.fromAccountAddress(connection, transactionPda),
    "fetch VaultTransaction",
  );
  const expected = buildExpected(vaultTx.message);
  const approveIx = multisig.instructions.proposalApprove({
    multisigPda, transactionIndex, member: wallet.publicKey,
  });
  const verifyArgs = (instructions) => ({
    multisig: multisigPda,
    transactionIndex: new anchor.BN(transactionIndex.toString()),
    vaultIndex: 0,
    numEphemeralSigners: 0,
    member: wallet.publicKey,
    action: { approve: {} },
    instructions,
  });
  const makeVerifyIx = (instructions) => program.methods
    .verifyProposal(verifyArgs(instructions))
    .accounts({ transaction: transactionPda, instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY })
    .instruction();
  const fetchProposal = () => withRetry(
    () => multisig.accounts.Proposal.fromAccountAddress(connection, proposalPda),
    "fetch Proposal",
  );

  let proposal = await fetchProposal();
  await sleep(PACE_MS);

  // --- 4. TAMPERED approval must fail --------------------------------------
  if (proposal.approved.length === 0) {
    step("attempt 1: TAMPERED expected data (lamports byte flipped) — must fail");
    const tampered = expected.map((ix) => ({ ...ix, data: Buffer.from(ix.data) }));
    tampered[0].data[7] ^= 0xff; // corrupt the u64 lamports amount of the transfer
    // skipPreflight so the failure is recorded ON-CHAIN, not just simulated
    const bad = await sendTx(connection, [await makeVerifyIx(tampered), approveIx], [wallet], { skipPreflight: true });
    if (!bad.err) throw new Error("TAMPERED approval unexpectedly SUCCEEDED — abort");
    console.log(`  on-chain failure recorded: ${bad.sig}`);
    console.log(`  err: ${JSON.stringify(bad.err)}`);
    const rec = await withRetry(
      () => connection.getTransaction(bad.sig, { maxSupportedTransactionVersion: 0, commitment: "confirmed" }),
      "fetch failed tx",
    );
    (rec?.meta?.logMessages || [])
      .filter((l) => /Error|mismatch/.test(l))
      .forEach((l) => console.log(`  ${l}`));
    proposal = await fetchProposal();
    if (proposal.approved.length !== 0) throw new Error("vote was recorded despite failure!");
    ok("tampered approval failed on-chain; no vote recorded (proposal.approved is empty)");
    await sleep(PACE_MS);
  } else {
    ok("proposal already approved — skipping tamper/approve attempts (resume)");
  }

  // --- 5. HONEST approval must succeed --------------------------------------
  if (proposal.approved.length === 0) {
    step("attempt 2: HONEST expected data (matches chain) — must succeed");
    const good = await sendTx(connection, [await makeVerifyIx(expected), approveIx], [wallet]);
    if (good.err) throw new Error(`honest approval failed: ${JSON.stringify(good.err)}`);
    proposal = await fetchProposal();
    if (proposal.approved.length !== 1) throw new Error("expected exactly 1 approval");
    ok(`honest approval landed: ${good.sig}`);
    ok(`proposal approved by: ${proposal.approved[0].toBase58()}`);
    await sleep(PACE_MS);
  }

  // --- 6. execute -----------------------------------------------------------
  if (proposal.status.__kind !== "Executed") {
    step("executing the vault transaction");
    const before = await withRetry(() => connection.getBalance(wallet.publicKey), "getBalance");
    const { instruction: execIx, lookupTableAccounts } = await withRetry(
      () => multisig.instructions.vaultTransactionExecute({
        connection, multisigPda, transactionIndex, member: wallet.publicKey,
      }), "build execute ix",
    );
    const execMsg = new TransactionMessage({
      payerKey: wallet.publicKey,
      recentBlockhash: (await withRetry(() => connection.getLatestBlockhash(), "getLatestBlockhash")).blockhash,
      instructions: [execIx],
    }).compileToV0Message(lookupTableAccounts);
    const execTx = new VersionedTransaction(execMsg);
    execTx.sign([wallet]);
    const execSig = bs58.encode(execTx.signatures[0]);
    await withRetry(() => connection.sendTransaction(execTx, { maxRetries: 5 }), "send execute");
    for (let i = 0; i < 40; i++) {
      const st = (await withRetry(() => connection.getSignatureStatuses([execSig]), "confirm execute")).value[0];
      if (st?.confirmationStatus === "confirmed" || st?.confirmationStatus === "finalized") {
        if (st.err) throw new Error(`execute failed: ${JSON.stringify(st.err)}`);
        break;
      }
      await sleep(2000);
    }
    const after = await withRetry(() => connection.getBalance(wallet.publicKey), "getBalance");
    ok(`executed: ${execSig}`);
    ok(`wallet balance delta: ${(after - before) / LAMPORTS_PER_SOL} SOL (transfer 0.001 minus fee)`);
  } else {
    ok("vault transaction already executed (resume)");
  }

  console.log("\n\x1b[32mE2E PASSED\x1b[0m — tampered approval rejected on-chain, honest approval verified, transfer executed.");
}

main().catch((e) => { console.error("\n\x1b[31mE2E FAILED:\x1b[0m", e); process.exit(1); });
