#!/usr/bin/env node
/**
 * End-to-end clear-signing scenario for a PROGRAMMATIC SIGNER: a Squads v4
 * vote cast by a Vector PDA (https://github.com/tiago18c/vector, Ed25519
 * program) and clear-signed by `verify_proposal_cpi`.
 *
 * A Vector account is a PDA `["vector", identity]` of the Vector program,
 * controlled by an off-chain ed25519 key that never signs a Solana
 * transaction. Every transaction is `[Advance, Passthrough]`, both top-level:
 *   - Advance      data `[0x01][sig 64]`, accounts `[pda (w), instructions sysvar]`.
 *                  The signature is over SHA256(sysvar[..sig] || nonce ||
 *                  identity || sysvar[sig+64..]), i.e. over the whole
 *                  transaction's instructions; on success the digest becomes
 *                  the next nonce.
 *   - Passthrough  data `[0x04][count]{num_accounts u8, data_len u16, data}*`,
 *                  accounts `[pda (w), instructions sysvar, then per
 *                  sub-instruction: program, its accounts...]`. Each
 *                  sub-instruction is CPI'd with the PDA promoted to signer.
 * So the Squads vote is never a top-level instruction, and `verify_proposal`
 * cannot see it. `verify_proposal_cpi(args)` runs as one of the
 * sub-instructions (the PDA signs it). It takes no location: it loads the
 * top-level instruction it descends from, requires it to be a Passthrough
 * (first data byte 4) of the program that owns the member account with the
 * member as account 0, and checks that Passthrough's sub-instruction list
 * (data from offset 1, accounts from index 2, consumed exactly): only this
 * program's instructions and the expected vote, and this very invocation.
 * One Advance authorizes every later Passthrough of the transaction, so every
 * OTHER top-level instruction of that Vector program must be an Advance.
 *
 * Flow:
 *   1. generate an ed25519 identity, initialize its Vector account (the PDA)
 *   2. create a Squads v4 multisig, threshold 1: the PDA is the only voter,
 *      the wallet can only initiate and execute
 *   3. fund vault 0, create vault transaction #1 (0.001 SOL vault -> wallet)
 *      + proposal, and a decoy #2 (drain to an attacker) + proposal
 *   4. NEGATIVE cases, each sent with skipPreflight so the failure is recorded
 *      on-chain; each must fail with the exact custom error, at the expected
 *      instruction index, and leave both proposals un-approved and the Vector
 *      nonce untouched:
 *        a. tampered expected data                    -> DataMismatch
 *        b. vote on the decoy, honest proposal shown  -> VoteProposalMismatch
 *        c3. one stray byte after the list            -> EmbeddedTrailingBytes
 *            (Vector rejects this too, but only after running the CPIs, so
 *            the clear-signing program is the one that raises)
 *        d. extra foreign sub-instruction (System)    -> ForbiddenInstruction
 *        e. verify_proposal_cpi top-level, by wallet  -> NotInvokedViaCpi
 *        f. a SECOND Passthrough{approve decoy #2} after the verified one,
 *           under the same Advance                    -> ForbiddenDriverInstruction
 *        f2. the same second Passthrough BEFORE the verified one
 *                                                     -> ForbiddenDriverInstruction
 *      Every failure must be raised by the clear-signing program itself (its
 *      AnchorError log line), not by Vector.
 *   5. HONEST: [Advance, Passthrough{assert_account_hash(multisig),
 *      verify_proposal_cpi(chain truth), proposal_approve}] -> must succeed,
 *      the proposal must list the PDA in `approved`. The one Advance is a
 *      sibling Vector instruction and must not trip the sibling rule.
 *   6. HONEST with compute budget instructions at TOP level (allowed there,
 *      not inside the list), on a third proposal:
 *      [SetComputeUnitLimit, Advance, Passthrough{...}, SetComputeUnitPrice]
 *      -> must succeed
 *   7. execute vault transaction #1 (wallet) and confirm the transfer landed
 *
 * Not covered: a second Advance in one transaction. Each Advance signs a
 * digest of the whole instructions sysvar except its own signature, so two
 * Advances would each have to sign the other's signature.
 *
 * Requirements: a LOCAL cluster that has Squads v4 (a surfpool mainnet fork),
 * the clear-signing program deployed, and Vector's Ed25519 program at its
 * declared id. Vector is deployed on no public cluster; when it is missing
 * and VECTOR_SO is set, it is installed with surfpool's `surfnet_writeProgram`
 * cheatcode. This script refuses to run against a non-local RPC.
 *
 * Env:
 *   RPC_URL    local cluster (default http://127.0.0.1:8999)
 *   WALLET     keypair path (default keys/e2e-wallet.json)
 *   VECTOR_SO  path to vector_ed25519.so, used only if Vector is not loaded
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bs58 = (() => { const m = require("bs58"); return m.default ?? m; })();
const {
  Connection, Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction,
  TransactionMessage, VersionedTransaction, SYSVAR_INSTRUCTIONS_PUBKEY, LAMPORTS_PER_SOL,
  ComputeBudgetProgram,
} = require("@solana/web3.js");
const multisig = require("@sqds/multisig");
const anchor = require("@anchor-lang/core");
const { trim, sha256Hex } = require("./program-hash.cjs");

const ROOT = path.join(__dirname, "..");
const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8999";
const WALLET_PATH = process.env.WALLET || path.join(ROOT, "keys", "e2e-wallet.json");
const VECTOR_SO = process.env.VECTOR_SO;
const IDL = JSON.parse(fs.readFileSync(path.join(ROOT, "idl", "squads_clear_signing.json")));
const IS_LOCAL = /^https?:\/\/(127\.0\.0\.1|localhost)(:\d+)?\/?$/.test(RPC_URL);

const VECTOR_PROGRAM_ID = new PublicKey("vectorcLBXJ2TuoKuUygkEi6FWqvBnbHDEDWoYamfjV");
const LOADER_V3 = new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111");
const VECTOR_INITIALIZE = 0;
const VECTOR_ADVANCE = 1;
const VECTOR_PASSTHROUGH = 4;
const SIG_LEN = 64;
const MAX_TX_SIZE = 1232;

const ok = (m) => console.log(`\x1b[32m✔\x1b[0m ${m}`);
const step = (m) => console.log(`\n\x1b[36m▶ ${m}\x1b[0m`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256 = (...parts) => {
  const h = crypto.createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
};

async function rpc(method, params) {
  const res = await fetch(RPC_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

// --- Vector client (mirrors sdk/ts/src/{instructions,digest}.ts) ------------

/** The off-chain identity: an ed25519 key that signs digests, never transactions. */
function generateIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const identity = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
  const [pda] = PublicKey.findProgramAddressSync([Buffer.from("vector"), identity], VECTOR_PROGRAM_ID);
  return { identity, pda, sign: (digest) => crypto.sign(null, digest, privateKey) };
}

function vectorInitializeIx(payer, id) {
  return new TransactionInstruction({
    programId: VECTOR_PROGRAM_ID,
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: id.pda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([Buffer.from([VECTOR_INITIALIZE]), id.identity]),
  });
}

function vectorAdvanceIx(id, signature) {
  return new TransactionInstruction({
    programId: VECTOR_PROGRAM_ID,
    keys: [
      { pubkey: id.pda, isSigner: false, isWritable: true },
      { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([Buffer.from([VECTOR_ADVANCE]), signature]),
  });
}

/** `trailing` appends raw bytes after the list (used by a negative case). */
function vectorPassthroughIx(id, subInstructions, { trailing = Buffer.alloc(0) } = {}) {
  const keys = [
    { pubkey: id.pda, isSigner: false, isWritable: true },
    { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
  ];
  const parts = [Buffer.from([VECTOR_PASSTHROUGH, subInstructions.length])];
  for (const ix of subInstructions) {
    keys.push({ pubkey: ix.programId, isSigner: false, isWritable: false });
    for (const meta of ix.keys) {
      // The PDA cannot sign the transaction; Vector promotes it inside the CPI.
      keys.push({ ...meta, isSigner: meta.isSigner && !meta.pubkey.equals(id.pda) });
    }
    const header = Buffer.alloc(3);
    header[0] = ix.keys.length;
    header.writeUInt16LE(ix.data.length, 1);
    parts.push(header, Buffer.from(ix.data));
  }
  return new TransactionInstruction({
    programId: VECTOR_PROGRAM_ID, keys, data: Buffer.concat([...parts, trailing]),
  });
}

/** Serialize a compiled legacy message into the instructions sysvar layout the
 *  runtime will expose (`construct_instructions_data`), with the per-account
 *  flags taken at MESSAGE level. `currentIndex` is the trailing u16.
 *  Models the runtime's demotion of a writable key that is called as a
 *  program; reserved-key demotion (sysvars / builtins passed writable) is not
 *  modelled — this scenario never passes one writable. */
function instructionsSysvar(message, currentIndex) {
  const ixs = message.compiledInstructions;
  const programIndexes = new Set(ixs.map((ix) => ix.programIdIndex));
  const loaderPresent = message.accountKeys.some((k) => k.equals(LOADER_V3));
  const flags = (i) =>
    (message.isAccountSigner(i) ? 1 : 0) |
    (message.isAccountWritable(i) && !(programIndexes.has(i) && !loaderPresent) ? 2 : 0);

  const head = Buffer.alloc(2 + 2 * ixs.length);
  head.writeUInt16LE(ixs.length, 0);
  const parts = [head];
  const offsets = [];
  let offset = head.length;
  for (const ix of ixs) {
    offsets.push(offset);
    const numAccounts = Buffer.alloc(2);
    numAccounts.writeUInt16LE(ix.accountKeyIndexes.length, 0);
    const dataLen = Buffer.alloc(2);
    dataLen.writeUInt16LE(ix.data.length, 0);
    const region = Buffer.concat([
      numAccounts,
      ...ix.accountKeyIndexes.map((i) => Buffer.concat([Buffer.from([flags(i)]), message.accountKeys[i].toBuffer()])),
      message.accountKeys[ix.programIdIndex].toBuffer(),
      dataLen,
      Buffer.from(ix.data),
    ]);
    parts.push(region);
    offset += region.length;
  }
  offsets.forEach((o, i) => head.writeUInt16LE(o, 2 + 2 * i));
  const footer = Buffer.alloc(2);
  footer.writeUInt16LE(currentIndex, 0);
  parts.push(footer);
  return { data: Buffer.concat(parts), offsets };
}

async function fetchNonce(connection, id) {
  const info = await connection.getAccountInfo(id.pda, "confirmed");
  if (!info) throw new Error(`vector account ${id.pda} does not exist`);
  return Buffer.from(info.data.subarray(0, 32));
}

/** Build and sign `[...before, Advance, Passthrough{subInstructions}, ...after]`
 *  as a legacy transaction: compile once with a placeholder signature to learn
 *  the exact sysvar bytes, sign the digest with the identity, then patch it
 *  in. `between` goes between the Advance and the Passthrough. */
async function buildVectorTx(connection, wallet, id, subInstructions, opts = {}) {
  const { before = [], between = [], after = [] } = opts;
  const nonce = await fetchNonce(connection, id);
  const { blockhash } = await connection.getLatestBlockhash("confirmed");
  const passthroughIx = vectorPassthroughIx(id, subInstructions, opts);
  const compile = (signature) => {
    const tx = new Transaction().add(
      ...before, vectorAdvanceIx(id, signature), ...between, passthroughIx, ...after);
    tx.recentBlockhash = blockhash;
    tx.feePayer = wallet.publicKey;
    return tx;
  };
  const advanceIndex = before.length;
  const { data, offsets } = instructionsSysvar(compile(Buffer.alloc(SIG_LEN)).compileMessage(), advanceIndex);
  const numAccounts = data.readUInt16LE(offsets[advanceIndex]);
  const sigStart = offsets[advanceIndex] + 2 + 33 * numAccounts + 32 + 2 + 1;
  const digest = sha256(data.subarray(0, sigStart), nonce, id.identity, data.subarray(sigStart + SIG_LEN));
  const tx = compile(id.sign(digest));
  tx.sign(wallet);
  return { tx, digest, nonce };
}

// --- generic helpers ---------------------------------------------------------

async function confirm(connection, sig) {
  for (let i = 0; i < 60; i++) {
    const st = (await connection.getSignatureStatuses([sig])).value[0];
    if (st && (st.confirmationStatus === "confirmed" || st.confirmationStatus === "finalized")) {
      return st.err;
    }
    await sleep(500);
  }
  throw new Error(`timed out confirming ${sig}`);
}

/** Send a signed legacy transaction; returns {sig, err, size, record}. */
async function sendSigned(connection, tx, { skipPreflight = false } = {}) {
  const raw = tx.serialize();
  const sig = bs58.encode(tx.signature);
  await connection.sendRawTransaction(raw, { skipPreflight, maxRetries: 5 });
  const err = await confirm(connection, sig);
  let record = null;
  for (let i = 0; i < 20 && !record; i++) {
    record = await connection.getTransaction(sig, { maxSupportedTransactionVersion: 0, commitment: "confirmed" });
    if (!record) await sleep(300);
  }
  return { sig, err, size: raw.length, record };
}

async function sendIxs(connection, instructions, signers, label) {
  const { blockhash } = await connection.getLatestBlockhash("confirmed");
  const tx = new Transaction().add(...instructions);
  tx.recentBlockhash = blockhash;
  tx.feePayer = signers[0].publicKey;
  tx.sign(...signers);
  const res = await sendSigned(connection, tx);
  if (res.err) {
    (res.record?.meta?.logMessages || []).forEach((l) => console.log(`  ${l}`));
    throw new Error(`${label} failed: ${JSON.stringify(res.err)} (${res.sig})`);
  }
  return res;
}

/** Expand the on-chain compiled message into ExpectedInstruction[] (as e2e.cjs). */
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

const printLogs = (record, filter) => (record?.meta?.logMessages || [])
  .filter((l) => filter.test(l))
  .forEach((l) => console.log(`    ${l}`));

async function main() {
  if (!IS_LOCAL) {
    throw new Error(`refusing to run against ${RPC_URL}: this scenario needs a local cluster (Vector is not deployed anywhere)`);
  }
  const connection = new Connection(RPC_URL, "confirmed");
  const wallet = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(WALLET_PATH))));
  console.log(`cluster: ${RPC_URL}`);
  console.log(`wallet:  ${wallet.publicKey.toBase58()}`);
  if ((await connection.getBalance(wallet.publicKey)) < 2 * LAMPORTS_PER_SOL) {
    const sig = await connection.requestAirdrop(wallet.publicKey, 20 * LAMPORTS_PER_SOL);
    await confirm(connection, sig);
  }

  // --- preflight: the three programs -----------------------------------------
  const provider = new anchor.AnchorProvider(connection, new anchor.Wallet(wallet), { commitment: "confirmed" });
  const program = new anchor.Program(IDL, provider);
  const programId = program.programId;
  const errorCode = (name) => {
    const e = IDL.errors.find((x) => x.name === name);
    if (!e) throw new Error(`error ${name} not in the IDL`);
    return e.code;
  };
  if (!(await connection.getAccountInfo(programId))) {
    throw new Error(`clear-signing program ${programId} not deployed on ${RPC_URL} — deploy target/deploy/squads_clear_signing.so first`);
  }
  ok(`squads_clear_signing deployed at ${programId.toBase58()}`);
  if (!(await connection.getAccountInfo(multisig.PROGRAM_ID))) {
    throw new Error(`Squads v4 (${multisig.PROGRAM_ID}) not on this cluster — use a surfpool mainnet fork`);
  }
  if (!(await connection.getAccountInfo(VECTOR_PROGRAM_ID))) {
    if (!VECTOR_SO) throw new Error(`Vector (${VECTOR_PROGRAM_ID}) not loaded and VECTOR_SO is not set`);
    step(`installing Vector Ed25519 at ${VECTOR_PROGRAM_ID.toBase58()} (surfnet_writeProgram)`);
    const so = fs.readFileSync(VECTOR_SO);
    const CHUNK = 4 * 1024 * 1024;
    for (let o = 0; o < so.length; o += CHUNK) {
      await rpc("surfnet_writeProgram", [VECTOR_PROGRAM_ID.toBase58(), so.subarray(o, o + CHUNK).toString("hex"), o]);
    }
    console.log(`  ${so.length} bytes, sha256 (trailing zeros trimmed) ${sha256Hex(trim(so))}`);
  }
  ok(`Vector Ed25519 loaded at ${VECTOR_PROGRAM_ID.toBase58()}`);

  // --- 1. the programmatic signer --------------------------------------------
  step("initializing a Vector account for a fresh ed25519 identity");
  const id = generateIdentity();
  await sendIxs(connection, [vectorInitializeIx(wallet.publicKey, id)], [wallet], "vector initialize");
  const vectorInfo = await connection.getAccountInfo(id.pda);
  if (!vectorInfo.owner.equals(VECTOR_PROGRAM_ID) || vectorInfo.data.length !== 65 ||
      !Buffer.from(vectorInfo.data.subarray(33)).equals(id.identity)) {
    throw new Error("vector account does not have the expected layout nonce[32] || bump || identity[32]");
  }
  ok(`identity ${bs58.encode(id.identity)} -> vector PDA (the Squads member) ${id.pda.toBase58()}`);

  // --- 2. multisig: the PDA is the only voter ----------------------------------
  step("creating Squads v4 multisig (threshold 1; PDA = Vote, wallet = Initiate + Execute)");
  const { Permission, Permissions } = multisig.types;
  const createKey = Keypair.generate();
  const [multisigPda] = multisig.getMultisigPda({ createKey: createKey.publicKey });
  const [programConfigPda] = multisig.getProgramConfigPda({});
  const programConfig = await multisig.accounts.ProgramConfig.fromAccountAddress(connection, programConfigPda);
  await sendIxs(connection, [multisig.instructions.multisigCreateV2({
    createKey: createKey.publicKey,
    creator: wallet.publicKey,
    multisigPda,
    configAuthority: null,
    timeLock: 0,
    members: [
      { key: id.pda, permissions: Permissions.fromPermissions([Permission.Vote]) },
      { key: wallet.publicKey, permissions: Permissions.fromPermissions([Permission.Initiate, Permission.Execute]) },
    ],
    threshold: 1,
    treasury: programConfig.treasury,
    rentCollector: null,
  })], [wallet, createKey], "multisig create");
  ok(`multisig: ${multisigPda.toBase58()}`);

  // --- 3. vault transaction #1 (honest) and #2 (decoy) -------------------------
  const [vaultPda] = multisig.getVaultPda({ multisigPda, index: 0 });
  step(`funding vault 0 (${vaultPda.toBase58()}) with 0.2 SOL`);
  await sendIxs(connection, [SystemProgram.transfer({
    fromPubkey: wallet.publicKey, toPubkey: vaultPda, lamports: 0.2 * LAMPORTS_PER_SOL,
  })], [wallet], "vault funding");

  const TRANSFER_LAMPORTS = 0.001 * LAMPORTS_PER_SOL;
  const createProposal = async (transactionIndex, toPubkey, lamports) => {
    const { blockhash } = await connection.getLatestBlockhash();
    const transactionMessage = new TransactionMessage({
      payerKey: vaultPda,
      recentBlockhash: blockhash,
      instructions: [SystemProgram.transfer({ fromPubkey: vaultPda, toPubkey, lamports })],
    });
    await sendIxs(connection, [
      multisig.instructions.vaultTransactionCreate({
        multisigPda, transactionIndex, creator: wallet.publicKey,
        vaultIndex: 0, ephemeralSigners: 0, transactionMessage,
      }),
      multisig.instructions.proposalCreate({ multisigPda, transactionIndex, creator: wallet.publicKey }),
    ], [wallet], `vault transaction #${transactionIndex} create`);
    return {
      transaction: multisig.getTransactionPda({ multisigPda, index: transactionIndex })[0],
      proposal: multisig.getProposalPda({ multisigPda, transactionIndex })[0],
    };
  };
  const transactionIndex = 1n;
  const decoyIndex = 2n;
  step("creating vault transaction #1 (0.001 SOL vault -> wallet) + proposal");
  const { transaction: transactionPda, proposal: proposalPda } =
    await createProposal(transactionIndex, wallet.publicKey, TRANSFER_LAMPORTS);
  ok(`vault transaction: ${transactionPda.toBase58()}`);
  ok(`proposal:          ${proposalPda.toBase58()}`);
  step("creating decoy vault transaction #2 (drain 0.1 SOL vault -> attacker) + proposal");
  const { proposal: decoyProposalPda } =
    await createProposal(decoyIndex, Keypair.generate().publicKey, 0.1 * LAMPORTS_PER_SOL);
  ok(`decoy proposal:    ${decoyProposalPda.toBase58()}`);
  const thirdIndex = 3n;
  step("creating vault transaction #3 (0.001 SOL vault -> wallet) + proposal, for the compute-budget case");
  const { transaction: thirdTransactionPda, proposal: thirdProposalPda } =
    await createProposal(thirdIndex, wallet.publicKey, TRANSFER_LAMPORTS);
  ok(`third proposal:    ${thirdProposalPda.toBase58()}`);

  // --- sub-instruction builders, from CHAIN truth ------------------------------
  const vaultTx = await multisig.accounts.VaultTransaction.fromAccountAddress(connection, transactionPda);
  const expected = buildExpected(vaultTx.message);
  const verifyArgs = (instructions, member, index) => ({
    multisig: multisigPda,
    transactionIndex: new anchor.BN(index.toString()),
    vaultIndex: 0,
    numEphemeralSigners: 0,
    member,
    action: { approve: {} },
    instructions,
  });
  const verifyCpiIx = ({
    instructions = expected, member = id.pda, index = transactionIndex,
    proposal = proposalPda, transaction = transactionPda,
  } = {}) => program.methods
    .verifyProposalCpi(verifyArgs(instructions, member, index))
    .accounts({ proposal, transaction, instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY, member })
    .instruction();
  const msInfo = await connection.getAccountInfo(multisigPda);
  const assertMultisigIx = await program.methods
    .assertAccountHash({ account: multisigPda, owner: multisig.PROGRAM_ID, expectedHash: sha256Hex(msInfo.data) })
    .accounts({ account: multisigPda })
    .instruction();
  const approveIx = multisig.instructions.proposalApprove({ multisigPda, transactionIndex, member: id.pda });
  const decoyApproveIx = multisig.instructions.proposalApprove({
    multisigPda, transactionIndex: decoyIndex, member: id.pda,
  });

  const fetchProposal = (p = proposalPda) => multisig.accounts.Proposal.fromAccountAddress(connection, p);
  /** Nothing may have changed: no vote on either proposal, nonce not advanced. */
  const assertUntouched = async (nonceBefore) => {
    const [honest, decoy, nonce] = [await fetchProposal(), await fetchProposal(decoyProposalPda), await fetchNonce(connection, id)];
    if (honest.approved.length !== 0 || decoy.approved.length !== 0) throw new Error("a vote was recorded despite the failure!");
    if (honest.status.__kind !== "Active" || decoy.status.__kind !== "Active") throw new Error("a proposal left the Active state");
    if (!nonce.equals(nonceBefore)) throw new Error("the Vector nonce advanced despite the failure");
  };

  // --- 4. NEGATIVE cases -------------------------------------------------------
  const tampered = expected.map((ix) => ({ ...ix, data: Buffer.from(ix.data) }));
  tampered[0].data[7] ^= 0xff; // corrupt the u64 lamports amount of the transfer
  const foreignIx = SystemProgram.transfer({ fromPubkey: wallet.publicKey, toPubkey: wallet.publicKey, lamports: 0 });
  // Index of the failing top-level instruction: 1 = the Passthrough (the error
  // surfaces from its CPI), 0 = verify_proposal_cpi sent on its own.
  const PASSTHROUGH = 1;
  // A second Passthrough of the same Vector program, voting on the decoy. On
  // its own Vector accepts it: the one Advance signs the whole transaction.
  const decoyPassthroughIx = vectorPassthroughIx(id, [decoyApproveIx]);
  const negativeCases = [
    {
      name: "a", label: "tampered expected data in the verify args (lamports byte flipped)",
      expect: "DataMismatch", ixIndex: PASSTHROUGH,
      build: async () => (await buildVectorTx(connection, wallet, id,
        [assertMultisigIx, await verifyCpiIx({ instructions: tampered }), approveIx])).tx,
    },
    {
      name: "b", label: "verify honest #1, vote cast on decoy #2",
      expect: "VoteProposalMismatch", ixIndex: PASSTHROUGH,
      build: async () => (await buildVectorTx(connection, wallet, id,
        [assertMultisigIx, await verifyCpiIx(), decoyApproveIx])).tx,
    },
    {
      name: "c3", label: "one stray byte after the passthrough list",
      expect: "EmbeddedTrailingBytes", ixIndex: PASSTHROUGH,
      build: async () => (await buildVectorTx(connection, wallet, id,
        [assertMultisigIx, await verifyCpiIx(), approveIx], { trailing: Buffer.from([0]) })).tx,
    },
    {
      name: "d", label: "extra foreign sub-instruction (System transfer of 0 lamports) after the vote",
      expect: "ForbiddenInstruction", ixIndex: PASSTHROUGH,
      build: async () => (await buildVectorTx(connection, wallet, id,
        [assertMultisigIx, await verifyCpiIx(), approveIx, foreignIx])).tx,
    },
    {
      name: "e", label: "verify_proposal_cpi as a top-level instruction, wallet as member",
      expect: "NotInvokedViaCpi", ixIndex: 0,
      build: async () => {
        const { blockhash } = await connection.getLatestBlockhash("confirmed");
        const tx = new Transaction().add(await verifyCpiIx({ member: wallet.publicKey }));
        tx.recentBlockhash = blockhash;
        tx.feePayer = wallet.publicKey;
        tx.sign(wallet);
        return tx;
      },
    },
    {
      name: "f", label: "second Passthrough{approve decoy #2} AFTER the verified Passthrough, same Advance",
      expect: "ForbiddenDriverInstruction", ixIndex: PASSTHROUGH,
      build: async () => (await buildVectorTx(connection, wallet, id,
        [assertMultisigIx, await verifyCpiIx(), approveIx], { after: [decoyPassthroughIx] })).tx,
    },
    {
      name: "f2", label: "second Passthrough{approve decoy #2} BEFORE the verified Passthrough, same Advance",
      expect: "ForbiddenDriverInstruction", ixIndex: PASSTHROUGH + 1,
      build: async () => (await buildVectorTx(connection, wallet, id,
        [assertMultisigIx, await verifyCpiIx(), approveIx], { between: [decoyPassthroughIx] })).tx,
    },
  ];

  const results = [];
  const record = (name, label, pass, detail) => {
    results.push({ name, label, pass, detail });
    console.log(`${pass ? "\x1b[32mPASS\x1b[0m" : "\x1b[31mFAIL\x1b[0m"} [${name}] ${label} — ${detail}`);
  };

  for (const c of negativeCases) {
    step(`case ${c.name}: ${c.label} — must fail with ${c.expect} (${errorCode(c.expect)})`);
    try {
      const nonceBefore = await fetchNonce(connection, id);
      const res = await sendSigned(connection, await c.build(), { skipPreflight: true });
      console.log(`  tx ${res.sig} (${res.size} bytes, ${res.record?.meta?.computeUnitsConsumed ?? "?"} CU)`);
      console.log(`  err: ${JSON.stringify(res.err)}`);
      printLogs(res.record, /Error|forbidden|mismatch|!= expected|failed/);
      const [index, kind] = res.err?.InstructionError ?? [];
      if (kind?.Custom !== errorCode(c.expect) || index !== c.ixIndex) {
        throw new Error(`expected InstructionError[${c.ixIndex}, Custom(${errorCode(c.expect)})] (${c.expect}), got ${JSON.stringify(res.err)}`);
      }
      // The error must come from the clear-signing program, not from Vector.
      const logs = res.record?.meta?.logMessages || [];
      const raised = logs.some((l) => l.includes(`Error Code: ${c.expect}. Error Number: ${errorCode(c.expect)}.`));
      const firstFailed = logs.find((l) => /^Program \S+ failed: /.test(l));
      if (!raised || !firstFailed?.startsWith(`Program ${programId.toBase58()} failed: `)) {
        throw new Error(`${c.expect} was not raised by the clear-signing program (first failure: ${firstFailed ?? "none"})`);
      }
      await assertUntouched(nonceBefore);
      record(c.name, c.label, true,
        `rejected on-chain by the clear-signing program with ${c.expect} (${kind.Custom}) at instruction ${index}; no vote, nonce unchanged`);
    } catch (e) {
      record(c.name, c.label, false, e.message);
    }
  }

  // --- 5. HONEST approval ------------------------------------------------------
  step("honest: [Advance, Passthrough{assert_account_hash(multisig), verify_proposal_cpi, proposal_approve}] — must succeed");
  let approved = false;
  const honestLabel = "Vector PDA approves via [Advance, Passthrough], clear-signed by verify_proposal_cpi (the Advance sibling is allowed)";
  try {
    const { tx, digest } = await buildVectorTx(connection, wallet, id,
      [assertMultisigIx, await verifyCpiIx(), approveIx]);
    const message = tx.compileMessage();
    const size = tx.serialize().length;
    if (size > MAX_TX_SIZE) throw new Error(`transaction is ${size} bytes (> ${MAX_TX_SIZE}); needs v0 + an address lookup table`);
    const res = await sendSigned(connection, tx);
    console.log(`  tx ${res.sig}`);
    printLogs(res.record, /clear-signing OK|account hash OK|Instruction: ProposalApprove|consumed/);
    if (res.err) throw new Error(`honest approval failed: ${JSON.stringify(res.err)}`);
    const proposal = await fetchProposal();
    if (proposal.approved.length !== 1 || !proposal.approved[0].equals(id.pda)) {
      throw new Error(`proposal.approved is [${proposal.approved.map((k) => k.toBase58())}], expected [${id.pda.toBase58()}]`);
    }
    if (proposal.status.__kind !== "Approved") throw new Error(`proposal status is ${proposal.status.__kind}, expected Approved`);
    if ((await fetchProposal(decoyProposalPda)).approved.length !== 0) throw new Error("the decoy proposal got a vote");
    if (!(await fetchNonce(connection, id)).equals(digest)) throw new Error("the Vector nonce is not the signed digest");
    if (!(res.record?.meta?.logMessages || []).some((l) => l.includes("clear-signing OK (cpi)"))) {
      throw new Error("verify_proposal_cpi's success log is missing from the transaction");
    }
    approved = true;
    const cu = res.record.meta.computeUnitsConsumed;
    console.log(`  compute units: ${cu} (default budget, no compute-budget instruction)`);
    console.log(`  transaction size: ${size} / ${MAX_TX_SIZE} bytes — LEGACY transaction, no address lookup table needed`);
    console.log(`    ${message.accountKeys.length} static account keys, 1 signature (the fee payer; the member never signs),`);
    console.log(`    instruction data: Advance ${message.compiledInstructions[0].data.length} + Passthrough ${message.compiledInstructions[1].data.length} bytes`);
    record("honest", honestLabel, true,
      `proposal.approved = [${id.pda.toBase58()}], status Approved; ${cu} CU, ${size} bytes (legacy)`);
  } catch (e) {
    record("honest", honestLabel, false, e.message);
  }

  // --- 6. HONEST, compute budget at top level -----------------------------------
  step("honest: [SetComputeUnitLimit, Advance, Passthrough{assert, verify_proposal_cpi(#3), approve #3}, SetComputeUnitPrice] — must succeed");
  const budgetLabel = "compute budget instructions at top level next to [Advance, Passthrough] are accepted";
  try {
    const thirdTx = await multisig.accounts.VaultTransaction.fromAccountAddress(connection, thirdTransactionPda);
    // Votes live in the proposal, not the multisig; re-hash anyway so the
    // assertion is against the account as it is now.
    const info = await connection.getAccountInfo(multisigPda);
    const assertIx = await program.methods
      .assertAccountHash({ account: multisigPda, owner: multisig.PROGRAM_ID, expectedHash: sha256Hex(info.data) })
      .accounts({ account: multisigPda })
      .instruction();
    const { tx, digest } = await buildVectorTx(connection, wallet, id, [
      assertIx,
      await verifyCpiIx({
        instructions: buildExpected(thirdTx.message), index: thirdIndex,
        proposal: thirdProposalPda, transaction: thirdTransactionPda,
      }),
      multisig.instructions.proposalApprove({ multisigPda, transactionIndex: thirdIndex, member: id.pda }),
    ], {
      before: [ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 })],
      after: [ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1 })],
    });
    const size = tx.serialize().length;
    if (size > MAX_TX_SIZE) throw new Error(`transaction is ${size} bytes (> ${MAX_TX_SIZE})`);
    const res = await sendSigned(connection, tx);
    console.log(`  tx ${res.sig}`);
    printLogs(res.record, /clear-signing OK|account hash OK|Instruction: ProposalApprove|ComputeBudget|consumed/);
    if (res.err) throw new Error(`approval with compute budget instructions failed: ${JSON.stringify(res.err)}`);
    const proposal = await fetchProposal(thirdProposalPda);
    if (proposal.approved.length !== 1 || !proposal.approved[0].equals(id.pda) || proposal.status.__kind !== "Approved") {
      throw new Error(`proposal #3 is ${proposal.status.__kind} with approved [${proposal.approved.map((k) => k.toBase58())}]`);
    }
    if ((await fetchProposal(decoyProposalPda)).approved.length !== 0) throw new Error("the decoy proposal got a vote");
    if (!(await fetchNonce(connection, id)).equals(digest)) throw new Error("the Vector nonce is not the signed digest");
    if (!(res.record?.meta?.logMessages || []).some((l) => l.includes("clear-signing OK (cpi)"))) {
      throw new Error("verify_proposal_cpi's success log is missing from the transaction");
    }
    const cu = res.record.meta.computeUnitsConsumed;
    record("budget", budgetLabel, true, `proposal #3 Approved by the PDA; ${cu} CU, ${size} bytes (legacy)`);
  } catch (e) {
    record("budget", budgetLabel, false, e.message);
  }

  // --- 7. execute --------------------------------------------------------------
  const executeLabel = "execute the approved vault transaction";
  if (approved) {
    step("executing the vault transaction (wallet has Execute)");
    try {
      const before = await connection.getBalance(vaultPda);
      const { instruction: execIx, lookupTableAccounts } = await multisig.instructions.vaultTransactionExecute({
        connection, multisigPda, transactionIndex, member: wallet.publicKey,
      });
      const execTx = new VersionedTransaction(new TransactionMessage({
        payerKey: wallet.publicKey,
        recentBlockhash: (await connection.getLatestBlockhash()).blockhash,
        instructions: [execIx],
      }).compileToV0Message(lookupTableAccounts));
      execTx.sign([wallet]);
      const execSig = await connection.sendTransaction(execTx, { maxRetries: 5 });
      const err = await confirm(connection, execSig);
      if (err) throw new Error(`execute failed: ${JSON.stringify(err)} (${execSig})`);
      const delta = before - (await connection.getBalance(vaultPda));
      if (delta !== TRANSFER_LAMPORTS) throw new Error(`vault balance changed by ${delta}, expected ${TRANSFER_LAMPORTS}`);
      record("execute", executeLabel, true, `vault paid out ${delta} lamports: ${execSig}`);
    } catch (e) {
      record("execute", executeLabel, false, e.message);
    }
  } else {
    record("execute", executeLabel, false, "skipped: the honest approval did not land");
  }

  // --- summary -----------------------------------------------------------------
  const failed = results.filter((r) => !r.pass);
  console.log("\nsummary:");
  for (const r of results) console.log(`  ${r.pass ? "PASS" : "FAIL"} [${r.name}] ${r.label}`);
  if (failed.length) {
    console.log(`\n\x1b[31mE2E-VECTOR FAILED\x1b[0m — ${failed.length} of ${results.length} cases failed.`);
    process.exit(1);
  }
  console.log(`\n\x1b[32mE2E-VECTOR PASSED\x1b[0m — ${results.length} cases.`);
}

main().catch((e) => { console.error("\n\x1b[31mE2E-VECTOR FAILED:\x1b[0m", e); process.exit(1); });
