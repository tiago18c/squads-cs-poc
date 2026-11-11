#!/usr/bin/env node
/**
 * End-to-end clear-signing scenario for a PROGRAMMATIC SIGNER: a Squads v4
 * vote cast by a Vector address (https://github.com/tiago18c/vector, the
 * single program for every signing scheme; the Ed25519 scheme is used here)
 * and clear-signed by `verify_proposal_cpi`.
 *
 * A Vector account is a PDA `["vector", [scheme], sha256(key)]` of the Vector
 * program, controlled by an off-chain key that never signs a Solana
 * transaction. Its data is `nonce[32] seed[32] scheme bump system_bump pad`
 * followed by the scheme's identity (the 32-byte public key for Ed25519).
 * Each account also has a "system PDA" `[vector address]` of the Vector
 * program, which is owned by the System program. Every transaction is
 * `[Advance, Passthrough]`, both top-level:
 *   - Advance      data `[0x00]{next_key, signature}*` (Ed25519: no next key,
 *                  64-byte signature), accounts `[vector (w).., instructions
 *                  sysvar]`. The message is SHA256 of the instructions sysvar
 *                  with this Advance's data after the discriminator cut out;
 *                  each listed account signs SHA256(message || nonce ||
 *                  vector address || next_key), which becomes its next nonce.
 *                  So one signature covers the whole transaction.
 *   - Passthrough  data `[0x01][num_signers][signs-as per signer: 0 = the
 *                  vector account, 1 = its system PDA][count]{num_accounts u8,
 *                  data_len u16, data}*`, accounts `[instructions sysvar,
 *                  signer vector accounts.., then per sub-instruction:
 *                  program, its accounts...]`. It checks no signature: it
 *                  requires the transaction's first Advance to come earlier
 *                  and list every signer, then CPIs each sub-instruction with
 *                  every signer's address promoted to signer.
 * So the Squads vote is never a top-level instruction, and `verify_proposal`
 * cannot see it. `verify_proposal_cpi(args)` runs as one of the
 * sub-instructions (the member signs that CPI, not the transaction). It takes
 * no location: it loads the top-level instruction it descends from, requires
 * it to be a Passthrough of the Vector program that invoked it directly, and
 * checks that Passthrough's sub-instruction list (consumed exactly): only this
 * program's instructions and the expected vote, and this very invocation.
 * One Advance authorizes every later Passthrough of the transaction, so every
 * OTHER top-level instruction of the Vector program must be an Advance.
 *
 * Flow:
 *   1. generate three ed25519 identities and initialize their Vector accounts:
 *      A (votes as the vector ACCOUNT), B (votes as its SYSTEM PDA) and C (a
 *      co-signer that is not a Squads member)
 *   2. create two Squads v4 multisigs, threshold 1; the wallet can only
 *      initiate and execute:
 *        msA: the only voter is A's vector account
 *        msB: the only voter is B's system PDA
 *   3. fund vault 0 of each and create vault transactions + proposals:
 *        msA: #1 honest (0.001 SOL vault -> wallet), #2 decoy (drain to an
 *             attacker), #3 (compute-budget case), #4 and #5 (two signers)
 *        msB: #1 honest, #2 decoy
 *   4. A. member = the vector ACCOUNT (signs-as 0). NEGATIVE cases, each sent
 *      with skipPreflight so the failure is recorded on-chain; each must fail
 *      with the exact error, at the expected instruction index, raised by the
 *      expected program, and leave both proposals un-approved and the Vector
 *      nonce untouched:
 *        a. tampered expected data                    -> DataMismatch
 *        b. vote on the decoy, honest proposal shown  -> VoteProposalMismatch
 *        c3. one stray byte after the list            -> EmbeddedTrailingBytes
 *            (Vector rejects this too, with InvalidInstructionData, but only
 *            after running the CPIs, so the clear-signing program is the one
 *            that raises)
 *        d. extra foreign sub-instruction (System)    -> ForbiddenInstruction
 *        e. verify_proposal_cpi top-level, by wallet  -> NotInvokedViaCpi
 *        f. a SECOND Passthrough{approve decoy #2} after the verified one,
 *           under the same Advance                    -> ForbiddenDriverInstruction
 *        f2. the same second Passthrough BEFORE the verified one
 *                                                     -> ForbiddenDriverInstruction
 *   5. HONEST: [Advance, Passthrough{assert_account_hash(multisig),
 *      verify_proposal_cpi(chain truth), proposal_approve}] -> must succeed,
 *      the proposal must list the member in `approved`. The one Advance is a
 *      sibling Vector instruction and must not trip the sibling rule.
 *   6. HONEST with compute budget instructions at TOP level (allowed there,
 *      not inside the list), on proposal #3:
 *      [SetComputeUnitLimit, Advance, Passthrough{...}, SetComputeUnitPrice]
 *   7. execute vault transaction #1 (wallet) and confirm the transfer landed
 *   8. B. member = a vector account's SYSTEM PDA (signs-as 1), on msB:
 *        sys-b. vote on the decoy, honest shown       -> VoteProposalMismatch
 *        sys-honest. the honest approval              -> must succeed
 *      The system PDA is left unfunded (0 lamports, no account): the script
 *      prints its balance, so a run shows whether Squads needs it funded.
 *   9. C. TWO signers in one Passthrough (two vector accounts in the Advance
 *      and in the Passthrough's signer list), only A being the Squads member:
 *        multi-1. signers [C, A] on #4                -> must succeed
 *        multi-2. signers [A, C] on #5                -> must succeed
 *   Every success case prints its compute units, its size and whether it fits
 *   a legacy transaction (it is sent as one).
 *
 * Not covered: a second Advance in one transaction. Each Advance signs a
 * digest of the whole instructions sysvar except its own data, so two
 * Advances would each have to sign the other's signature.
 *
 * Requirements: a LOCAL fork of DEVNET (surfpool `--network devnet`), where
 * both Squads v4 and Vector (74mXFW7BSAAwc6zQC2uYKuDcWnz17HHXMWqLnEeg9BJv) are
 * deployed, with the clear-signing program deployed on the fork. This script
 * refuses to run against a non-local RPC.
 *
 * Env:
 *   RPC_URL    local cluster (default http://127.0.0.1:8999)
 *   WALLET     keypair path (default keys/e2e-wallet.json)
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
const { sha256Hex } = require("./program-hash.cjs");

const ROOT = path.join(__dirname, "..");
const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8999";
const WALLET_PATH = process.env.WALLET || path.join(ROOT, "keys", "e2e-wallet.json");
const IDL = JSON.parse(fs.readFileSync(path.join(ROOT, "idl", "squads_clear_signing.json")));
const IS_LOCAL = /^https?:\/\/(127\.0\.0\.1|localhost)(:\d+)?\/?$/.test(RPC_URL);

const VECTOR_PROGRAM_ID = new PublicKey("74mXFW7BSAAwc6zQC2uYKuDcWnz17HHXMWqLnEeg9BJv");
const LOADER_V3 = new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111");
const VECTOR_ADVANCE = 0;
const VECTOR_PASSTHROUGH = 1;
const VECTOR_INITIALIZE = 2;
const SCHEME_ED25519 = 1;
const SIGNS_AS_VECTOR = 0;
const SIGNS_AS_SYSTEM = 1;
const VECTOR_HEADER_LEN = 68; // nonce[32] seed[32] scheme bump system_bump pad
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

// --- Vector client (mirrors sdk/ts/src/{scheme,instructions,digest}.ts) -----

/** The off-chain identity: an ed25519 key that signs digests, never
 *  transactions. `pda` is the vector account, `systemPda` its system PDA. */
function generateIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const identity = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
  const seed = sha256(identity);
  const [pda, bump] = PublicKey.findProgramAddressSync(
    [Buffer.from("vector"), Buffer.from([SCHEME_ED25519]), seed], VECTOR_PROGRAM_ID);
  const [systemPda, systemBump] = PublicKey.findProgramAddressSync([pda.toBuffer()], VECTOR_PROGRAM_ID);
  return { identity, seed, pda, bump, systemPda, systemBump, sign: (digest) => crypto.sign(null, digest, privateKey) };
}

function vectorInitializeIx(payer, id) {
  return new TransactionInstruction({
    programId: VECTOR_PROGRAM_ID,
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: id.pda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([Buffer.from([VECTOR_INITIALIZE, SCHEME_ED25519]), id.identity]),
  });
}

/** One Advance for every identity in `ids`; Ed25519 has no next key, so the
 *  data is the discriminator and one signature per account, in order. */
function vectorAdvanceIx(ids, signatures) {
  return new TransactionInstruction({
    programId: VECTOR_PROGRAM_ID,
    keys: [
      ...ids.map((id) => ({ pubkey: id.pda, isSigner: false, isWritable: true })),
      { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([Buffer.from([VECTOR_ADVANCE]), ...signatures]),
  });
}

/** The address a Passthrough signer `{id, system}` signs as. */
const signerAddress = ({ id, system = false }) => (system ? id.systemPda : id.pda);

/** `signers` is `[{id, system}]`: each signs as its vector account, or with
 *  `system` as its system PDA. `trailing` appends raw bytes after the list
 *  (used by a negative case). */
function vectorPassthroughIx(signers, subInstructions, { trailing = Buffer.alloc(0) } = {}) {
  const keys = [
    { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
    ...signers.map(({ id }) => ({ pubkey: id.pda, isSigner: false, isWritable: false })),
  ];
  const addresses = signers.map(signerAddress);
  const parts = [
    Buffer.from([VECTOR_PASSTHROUGH, signers.length]),
    Buffer.from(signers.map(({ system = false }) => (system ? SIGNS_AS_SYSTEM : SIGNS_AS_VECTOR))),
    Buffer.from([subInstructions.length]),
  ];
  for (const ix of subInstructions) {
    keys.push({ pubkey: ix.programId, isSigner: false, isWritable: false });
    for (const meta of ix.keys) {
      // A signer address cannot sign the transaction; Vector promotes it inside the CPI.
      keys.push({ ...meta, isSigner: meta.isSigner && !addresses.some((a) => a.equals(meta.pubkey)) });
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

/** Build and sign `[...before, Advance, ...between, Passthrough{subInstructions},
 *  ...after]` as a legacy transaction. `signers` is the Passthrough's signer
 *  list `[{id, system}]`; the Advance lists each of their vector accounts
 *  once, in that order. Compile once with placeholder signatures to learn the
 *  exact sysvar bytes, hash them without the Advance's data into the message,
 *  have each identity sign SHA256(message || its nonce || its address), then
 *  patch the signatures in. Returns the digests (the accounts' next nonces)
 *  aligned with `ids`. */
async function buildVectorTx(connection, wallet, signers, subInstructions, opts = {}) {
  const { before = [], between = [], after = [] } = opts;
  const ids = signers.map((s) => s.id).filter((id, i, all) => all.indexOf(id) === i);
  const nonces = [];
  for (const id of ids) nonces.push(await fetchNonce(connection, id));
  const { blockhash } = await connection.getLatestBlockhash("confirmed");
  const passthroughIx = vectorPassthroughIx(signers, subInstructions, opts);
  const compile = (signatures) => {
    const tx = new Transaction().add(
      ...before, vectorAdvanceIx(ids, signatures), ...between, passthroughIx, ...after);
    tx.recentBlockhash = blockhash;
    tx.feePayer = wallet.publicKey;
    return tx;
  };
  const advanceIndex = before.length;
  const { data, offsets } = instructionsSysvar(
    compile(ids.map(() => Buffer.alloc(SIG_LEN))).compileMessage(), advanceIndex);
  const numAccounts = data.readUInt16LE(offsets[advanceIndex]);
  // Everything after the Advance's discriminator is cut out of the message.
  const cutStart = offsets[advanceIndex] + 2 + 33 * numAccounts + 32 + 2 + 1;
  const message = sha256(data.subarray(0, cutStart), data.subarray(cutStart + SIG_LEN * ids.length));
  const digests = ids.map((id, i) => sha256(message, nonces[i], id.pda.toBuffer()));
  const tx = compile(ids.map((id, i) => id.sign(digests[i])));
  tx.sign(wallet);
  return { tx, ids, digests, nonces, advanceIndex };
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
    throw new Error(`refusing to run against ${RPC_URL}: this scenario needs a local cluster (a surfpool fork of devnet)`);
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
    throw new Error(`Squads v4 (${multisig.PROGRAM_ID}) not on this cluster — use a surfpool fork of devnet`);
  }
  const vectorProgram = await connection.getAccountInfo(VECTOR_PROGRAM_ID);
  if (!vectorProgram || !vectorProgram.executable) {
    throw new Error(`Vector (${VECTOR_PROGRAM_ID}) is not a program on ${RPC_URL} — it is deployed on devnet: start the local cluster as a fork of devnet (surfpool start --network devnet)`);
  }
  ok(`Vector loaded at ${VECTOR_PROGRAM_ID.toBase58()}`);

  // --- 1. the programmatic signers ---------------------------------------------
  step("initializing Vector accounts for three fresh ed25519 identities");
  const initIdentity = async (role) => {
    const id = generateIdentity();
    await sendIxs(connection, [vectorInitializeIx(wallet.publicKey, id)], [wallet], "vector initialize");
    const info = await connection.getAccountInfo(id.pda);
    const d = Buffer.from(info.data);
    if (!info.owner.equals(VECTOR_PROGRAM_ID) || d.length !== VECTOR_HEADER_LEN + 32 ||
        !d.subarray(32, 64).equals(id.seed) || d[64] !== SCHEME_ED25519 || d[65] !== id.bump ||
        d[66] !== id.systemBump || !d.subarray(VECTOR_HEADER_LEN).equals(id.identity)) {
      throw new Error("vector account does not have the expected layout nonce[32] seed[32] scheme bump system_bump pad || identity[32]");
    }
    ok(`${role}: identity ${bs58.encode(id.identity)} -> vector account ${id.pda.toBase58()}, system PDA ${id.systemPda.toBase58()}`);
    return id;
  };
  const idA = await initIdentity("A (votes as the vector account)");
  const idB = await initIdentity("B (votes as its system PDA)");
  const idC = await initIdentity("C (co-signer, not a Squads member)");
  const signerA = { id: idA };
  const signerB = { id: idB, system: true };
  const signerC = { id: idC };

  // --- 2./3. multisigs, vaults, vault transactions ------------------------------
  const { Permission, Permissions } = multisig.types;
  const [programConfigPda] = multisig.getProgramConfigPda({});
  const programConfig = await multisig.accounts.ProgramConfig.fromAccountAddress(connection, programConfigPda);
  const TRANSFER_LAMPORTS = 0.001 * LAMPORTS_PER_SOL;

  /** A multisig whose only voter is `member`, with a funded vault 0. */
  const createMultisig = async (name, member) => {
    step(`creating Squads v4 multisig ${name} (threshold 1; ${member.toBase58()} = Vote, wallet = Initiate + Execute)`);
    const createKey = Keypair.generate();
    const [multisigPda] = multisig.getMultisigPda({ createKey: createKey.publicKey });
    await sendIxs(connection, [multisig.instructions.multisigCreateV2({
      createKey: createKey.publicKey,
      creator: wallet.publicKey,
      multisigPda,
      configAuthority: null,
      timeLock: 0,
      members: [
        { key: member, permissions: Permissions.fromPermissions([Permission.Vote]) },
        { key: wallet.publicKey, permissions: Permissions.fromPermissions([Permission.Initiate, Permission.Execute]) },
      ],
      threshold: 1,
      treasury: programConfig.treasury,
      rentCollector: null,
    })], [wallet, createKey], "multisig create");
    ok(`multisig ${name}: ${multisigPda.toBase58()}`);
    const [vaultPda] = multisig.getVaultPda({ multisigPda, index: 0 });
    await sendIxs(connection, [SystemProgram.transfer({
      fromPubkey: wallet.publicKey, toPubkey: vaultPda, lamports: 0.2 * LAMPORTS_PER_SOL,
    })], [wallet], "vault funding");
    ok(`vault 0 (${vaultPda.toBase58()}) funded with 0.2 SOL`);
    return { name, multisigPda, vaultPda, member };
  };

  /** Vault transaction `index` of `ms` (a transfer out of the vault) and its
   *  proposal; `expected` is read back from CHAIN truth. */
  const createProposal = async (ms, index, toPubkey, lamports, what) => {
    step(`creating ${ms.name} vault transaction #${index} (${what}) + proposal`);
    const { blockhash } = await connection.getLatestBlockhash();
    const transactionMessage = new TransactionMessage({
      payerKey: ms.vaultPda,
      recentBlockhash: blockhash,
      instructions: [SystemProgram.transfer({ fromPubkey: ms.vaultPda, toPubkey, lamports })],
    });
    await sendIxs(connection, [
      multisig.instructions.vaultTransactionCreate({
        multisigPda: ms.multisigPda, transactionIndex: index, creator: wallet.publicKey,
        vaultIndex: 0, ephemeralSigners: 0, transactionMessage,
      }),
      multisig.instructions.proposalCreate({ multisigPda: ms.multisigPda, transactionIndex: index, creator: wallet.publicKey }),
    ], [wallet], `vault transaction #${index} create`);
    const transaction = multisig.getTransactionPda({ multisigPda: ms.multisigPda, index })[0];
    const proposal = multisig.getProposalPda({ multisigPda: ms.multisigPda, transactionIndex: index })[0];
    const vaultTx = await multisig.accounts.VaultTransaction.fromAccountAddress(connection, transaction);
    ok(`vault transaction ${transaction.toBase58()}, proposal ${proposal.toBase58()}`);
    return { ms, index, transaction, proposal, expected: buildExpected(vaultTx.message) };
  };
  const honestTransfer = "0.001 SOL vault -> wallet";
  const decoyTransfer = "decoy: drain 0.1 SOL vault -> attacker";
  const attacker = Keypair.generate().publicKey;

  const msA = await createMultisig("msA", idA.pda);
  const honestA = await createProposal(msA, 1n, wallet.publicKey, TRANSFER_LAMPORTS, honestTransfer);
  const decoyA = await createProposal(msA, 2n, attacker, 0.1 * LAMPORTS_PER_SOL, decoyTransfer);
  const budgetA = await createProposal(msA, 3n, wallet.publicKey, TRANSFER_LAMPORTS, `${honestTransfer}, for the compute-budget case`);
  const multi1A = await createProposal(msA, 4n, wallet.publicKey, TRANSFER_LAMPORTS, `${honestTransfer}, for the two-signer case [C, A]`);
  const multi2A = await createProposal(msA, 5n, wallet.publicKey, TRANSFER_LAMPORTS, `${honestTransfer}, for the two-signer case [A, C]`);
  const msB = await createMultisig("msB", idB.systemPda);
  const honestB = await createProposal(msB, 1n, wallet.publicKey, TRANSFER_LAMPORTS, honestTransfer);
  const decoyB = await createProposal(msB, 2n, attacker, 0.1 * LAMPORTS_PER_SOL, decoyTransfer);

  // --- sub-instruction builders -------------------------------------------------
  /** verify_proposal_cpi for proposal `p`, by its multisig's voting member. */
  const verifyCpiIx = (p, { instructions = p.expected, member = p.ms.member } = {}) => program.methods
    .verifyProposalCpi({
      multisig: p.ms.multisigPda,
      transactionIndex: new anchor.BN(p.index.toString()),
      vaultIndex: 0,
      numEphemeralSigners: 0,
      member,
      action: { approve: {} },
      instructions,
    })
    .accounts({ proposal: p.proposal, transaction: p.transaction, instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY, member })
    .instruction();
  /** assert_account_hash of the multisig account as it is now, owner Squads. */
  const assertMultisigIx = async (ms) => {
    const info = await connection.getAccountInfo(ms.multisigPda);
    return program.methods
      .assertAccountHash({ account: ms.multisigPda, owner: multisig.PROGRAM_ID, expectedHash: sha256Hex(info.data) })
      .accounts({ account: ms.multisigPda })
      .instruction();
  };
  const approveIx = (p) => multisig.instructions.proposalApprove({
    multisigPda: p.ms.multisigPda, transactionIndex: p.index, member: p.ms.member,
  });
  /** assert_program_deploy_slot for `programKey`, with the slot read from chain:
   *  pins the driver's current deployment from inside its own instruction list. */
  const deploySlotIx = async (programKey) => {
    const info = await connection.getAccountInfo(programKey);
    const programData = new PublicKey(info.data.subarray(4, 36));
    const slot = (await connection.getAccountInfo(programData)).data.readBigUInt64LE(4);
    return program.methods
      .assertProgramDeploySlot({ program: programKey, expectedSlot: new anchor.BN(slot.toString()) })
      .accounts({ program: programKey, programData })
      .instruction();
  };
  /** The honest list: [assert_account_hash(multisig), assert_program_deploy_slot(Vector),
   *  verify_proposal_cpi, proposal_approve]. */
  const honestList = async (p) => [
    await assertMultisigIx(p.ms), await deploySlotIx(VECTOR_PROGRAM_ID), await verifyCpiIx(p), approveIx(p),
  ];

  const fetchProposal = (p) => multisig.accounts.Proposal.fromAccountAddress(connection, p.proposal);
  /** Nothing may have changed: no vote on any of `proposals`, nonce not advanced. */
  const assertUntouched = async (proposals, id, nonceBefore) => {
    for (const p of proposals) {
      const state = await fetchProposal(p);
      if (state.approved.length !== 0 || state.rejected.length !== 0 || state.cancelled.length !== 0) {
        throw new Error(`a vote was recorded on ${p.ms.name} #${p.index} despite the failure!`);
      }
      if (state.status.__kind !== "Active") throw new Error(`${p.ms.name} #${p.index} left the Active state`);
    }
    if (!(await fetchNonce(connection, id)).equals(nonceBefore)) throw new Error("the Vector nonce advanced despite the failure");
  };

  const results = [];
  const record = (name, label, pass, detail) => {
    results.push({ name, label, pass, detail });
    console.log(`${pass ? "\x1b[32mPASS\x1b[0m" : "\x1b[31mFAIL\x1b[0m"} [${name}] ${label} — ${detail}`);
  };

  /** A negative case: `c.build()` must fail on-chain with `c.expect` of the
   *  clear-signing program at top-level instruction `c.ixIndex`, and leave
   *  `c.proposals` and the nonce of `c.id` untouched. */
  const runNegative = async (c) => {
    step(`case ${c.name}: ${c.label} — must fail with ${c.expect} (${errorCode(c.expect)})`);
    try {
      const nonceBefore = await fetchNonce(connection, c.id);
      const res = await sendSigned(connection, await c.build(), { skipPreflight: true });
      console.log(`  tx ${res.sig} (${res.size} bytes, ${res.record?.meta?.computeUnitsConsumed ?? "?"} CU)`);
      console.log(`  err: ${JSON.stringify(res.err)}`);
      printLogs(res.record, /Error|forbidden|mismatch|!= expected|failed/);
      const logs = res.record?.meta?.logMessages || [];
      // The innermost program that failed is the one that raised the error.
      const firstFailed = logs.find((l) => /^Program \S+ failed: /.test(l));
      console.log(`  raised by: ${firstFailed ?? "no program failure in the logs"}`);
      const [index, kind] = res.err?.InstructionError ?? [];
      if (kind?.Custom !== errorCode(c.expect) || index !== c.ixIndex) {
        throw new Error(`expected InstructionError[${c.ixIndex}, Custom(${errorCode(c.expect)})] (${c.expect}), got ${JSON.stringify(res.err)}`);
      }
      // The error must come from the clear-signing program, not from Vector.
      const raised = logs.some((l) => l.includes(`Error Code: ${c.expect}. Error Number: ${errorCode(c.expect)}.`));
      if (!raised || !firstFailed?.startsWith(`Program ${programId.toBase58()} failed: `)) {
        throw new Error(`${c.expect} was not raised by the clear-signing program (first failure: ${firstFailed ?? "none"})`);
      }
      await assertUntouched(c.proposals, c.id, nonceBefore);
      record(c.name, c.label, true,
        `rejected on-chain by the clear-signing program with ${c.expect} (${kind.Custom}) at instruction ${index}; no vote, nonce unchanged`);
    } catch (e) {
      record(c.name, c.label, false, e.message);
    }
  };

  /** A success case: [...before, Advance, Passthrough{honest list for `c.p`},
   *  ...after] signed by `c.signers` must land as a legacy transaction, record
   *  the member's approval on `c.p` only, and move every signer's nonce to the
   *  digest it signed. Returns whether it passed. */
  const runHonest = async (c) => {
    step(`${c.name}: ${c.shape} — must succeed`);
    try {
      const member = c.p.ms.member;
      const built = await buildVectorTx(connection, wallet, c.signers, await honestList(c.p), c.opts);
      const { tx } = built;
      const message = tx.compileMessage();
      const size = tx.serialize({ verifySignatures: false }).length;
      const fits = size <= MAX_TX_SIZE;
      console.log(`  transaction size: ${size} / ${MAX_TX_SIZE} bytes — ${fits ? "fits a LEGACY transaction, no address lookup table needed" : "does NOT fit a legacy transaction"}`);
      console.log(`    ${message.accountKeys.length} static account keys, 1 signature (the fee payer; the member never signs),`);
      console.log(`    instruction data: Advance ${message.compiledInstructions[built.advanceIndex].data.length} + Passthrough ${message.compiledInstructions[built.advanceIndex + 1].data.length} bytes`);
      if (!fits) throw new Error(`transaction is ${size} bytes (> ${MAX_TX_SIZE}); needs v0 + an address lookup table`);
      if (message.accountKeys.slice(0, message.header.numRequiredSignatures).some((k) => k.equals(member))) {
        throw new Error("the member signs the transaction");
      }
      const res = await sendSigned(connection, tx);
      console.log(`  tx ${res.sig}`);
      printLogs(res.record, /clear-signing OK|account hash OK|Instruction: ProposalApprove|ComputeBudget|consumed|failed|Error/);
      if (res.err) throw new Error(`approval failed: ${JSON.stringify(res.err)}`);
      const proposal = await fetchProposal(c.p);
      if (proposal.approved.length !== 1 || !proposal.approved[0].equals(member)) {
        throw new Error(`proposal.approved is [${proposal.approved.map((k) => k.toBase58())}], expected [${member.toBase58()}]`);
      }
      if (proposal.status.__kind !== "Approved") throw new Error(`proposal status is ${proposal.status.__kind}, expected Approved`);
      for (const decoy of c.decoys) {
        if ((await fetchProposal(decoy)).approved.length !== 0) throw new Error("the decoy proposal got a vote");
      }
      for (const [i, id] of built.ids.entries()) {
        if (!(await fetchNonce(connection, id)).equals(built.digests[i])) {
          throw new Error(`the nonce of vector account ${id.pda.toBase58()} is not the digest it signed`);
        }
      }
      if (!(res.record?.meta?.logMessages || []).some((l) => l.includes("clear-signing OK (cpi)"))) {
        throw new Error("verify_proposal_cpi's success log is missing from the transaction");
      }
      const cu = res.record.meta.computeUnitsConsumed;
      console.log(`  compute units: ${cu}${c.opts ? "" : " (default budget, no compute-budget instruction)"}`);
      record(c.name, c.label, true,
        `${c.p.ms.name} #${c.p.index} approved = [${member.toBase58()}], status Approved; ${cu} CU, ${size} bytes (legacy)`);
      return true;
    } catch (e) {
      record(c.name, c.label, false, e.message);
      return false;
    }
  };

  // --- 4. A: member = the vector account. NEGATIVE cases -------------------------
  const tampered = honestA.expected.map((ix) => ({ ...ix, data: Buffer.from(ix.data) }));
  tampered[0].data[7] ^= 0xff; // corrupt the u64 lamports amount of the transfer
  const foreignIx = SystemProgram.transfer({ fromPubkey: wallet.publicKey, toPubkey: wallet.publicKey, lamports: 0 });
  // Index of the failing top-level instruction: 1 = the Passthrough (the error
  // surfaces from its CPI), 0 = verify_proposal_cpi sent on its own.
  const PASSTHROUGH = 1;
  // A second Passthrough of the Vector program, voting on the decoy. On its
  // own Vector accepts it: the one Advance signs the whole transaction.
  const decoyPassthroughIx = vectorPassthroughIx([signerA], [approveIx(decoyA)]);
  const untouchedA = { id: idA, proposals: [honestA, decoyA] };
  const negativeCases = [
    {
      name: "a", label: "tampered expected data in the verify args (lamports byte flipped)",
      expect: "DataMismatch", ixIndex: PASSTHROUGH,
      build: async () => (await buildVectorTx(connection, wallet, [signerA],
        [await assertMultisigIx(msA), await verifyCpiIx(honestA, { instructions: tampered }), approveIx(honestA)])).tx,
    },
    {
      name: "b", label: "verify honest #1, vote cast on decoy #2",
      expect: "VoteProposalMismatch", ixIndex: PASSTHROUGH,
      build: async () => (await buildVectorTx(connection, wallet, [signerA],
        [await assertMultisigIx(msA), await verifyCpiIx(honestA), approveIx(decoyA)])).tx,
    },
    {
      name: "c3", label: "one stray byte after the passthrough list",
      expect: "EmbeddedTrailingBytes", ixIndex: PASSTHROUGH,
      build: async () => (await buildVectorTx(connection, wallet, [signerA],
        await honestList(honestA), { trailing: Buffer.from([0]) })).tx,
    },
    {
      name: "d", label: "extra foreign sub-instruction (System transfer of 0 lamports) after the vote",
      expect: "ForbiddenInstruction", ixIndex: PASSTHROUGH,
      build: async () => (await buildVectorTx(connection, wallet, [signerA],
        [...await honestList(honestA), foreignIx])).tx,
    },
    {
      name: "e", label: "verify_proposal_cpi as a top-level instruction, wallet as member",
      expect: "NotInvokedViaCpi", ixIndex: 0,
      build: async () => {
        const { blockhash } = await connection.getLatestBlockhash("confirmed");
        const tx = new Transaction().add(await verifyCpiIx(honestA, { member: wallet.publicKey }));
        tx.recentBlockhash = blockhash;
        tx.feePayer = wallet.publicKey;
        tx.sign(wallet);
        return tx;
      },
    },
    {
      name: "f", label: "second Passthrough{approve decoy #2} AFTER the verified Passthrough, same Advance",
      expect: "ForbiddenDriverInstruction", ixIndex: PASSTHROUGH,
      build: async () => (await buildVectorTx(connection, wallet, [signerA],
        await honestList(honestA), { after: [decoyPassthroughIx] })).tx,
    },
    {
      name: "f2", label: "second Passthrough{approve decoy #2} BEFORE the verified Passthrough, same Advance",
      expect: "ForbiddenDriverInstruction", ixIndex: PASSTHROUGH + 1,
      build: async () => (await buildVectorTx(connection, wallet, [signerA],
        await honestList(honestA), { between: [decoyPassthroughIx] })).tx,
    },
  ];
  for (const c of negativeCases) await runNegative({ ...untouchedA, ...c });

  // --- 5. A: HONEST approval -----------------------------------------------------
  const approved = await runHonest({
    name: "honest",
    label: "vector ACCOUNT approves via [Advance, Passthrough], clear-signed by verify_proposal_cpi (the Advance sibling is allowed)",
    shape: "[Advance, Passthrough{assert_account_hash(multisig), verify_proposal_cpi, proposal_approve}]",
    signers: [signerA], p: honestA, decoys: [decoyA],
  });

  // --- 6. A: HONEST, compute budget at top level ----------------------------------
  await runHonest({
    name: "budget",
    label: "compute budget instructions at top level next to [Advance, Passthrough] are accepted",
    shape: "[SetComputeUnitLimit, Advance, Passthrough{assert, verify_proposal_cpi(#3), approve #3}, SetComputeUnitPrice]",
    signers: [signerA], p: budgetA, decoys: [decoyA],
    opts: {
      before: [ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 })],
      after: [ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1 })],
    },
  });

  // --- 7. execute ------------------------------------------------------------------
  const executeLabel = "execute the approved vault transaction";
  if (approved) {
    step("executing msA vault transaction #1 (wallet has Execute)");
    try {
      const before = await connection.getBalance(msA.vaultPda);
      const { instruction: execIx, lookupTableAccounts } = await multisig.instructions.vaultTransactionExecute({
        connection, multisigPda: msA.multisigPda, transactionIndex: honestA.index, member: wallet.publicKey,
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
      const delta = before - (await connection.getBalance(msA.vaultPda));
      if (delta !== TRANSFER_LAMPORTS) throw new Error(`vault balance changed by ${delta}, expected ${TRANSFER_LAMPORTS}`);
      record("execute", executeLabel, true, `vault paid out ${delta} lamports: ${execSig}`);
    } catch (e) {
      record("execute", executeLabel, false, e.message);
    }
  } else {
    record("execute", executeLabel, false, "skipped: the honest approval did not land");
  }

  // --- 8. B: member = a vector account's SYSTEM PDA --------------------------------
  const systemPdaInfo = await connection.getAccountInfo(idB.systemPda);
  console.log(`\nsystem PDA ${idB.systemPda.toBase58()} (the member of msB): ${
    systemPdaInfo ? `${systemPdaInfo.lamports} lamports, owner ${systemPdaInfo.owner.toBase58()}` : "0 lamports, account does not exist"
  } — not funded by this script; Squads' vote takes it writable`);
  await runNegative({
    name: "sys-b", label: "system PDA member: verify honest #1, vote cast on decoy #2",
    expect: "VoteProposalMismatch", ixIndex: PASSTHROUGH, id: idB, proposals: [honestB, decoyB],
    build: async () => (await buildVectorTx(connection, wallet, [signerB],
      [await assertMultisigIx(msB), await verifyCpiIx(honestB), approveIx(decoyB)])).tx,
  });
  await runHonest({
    name: "sys-honest",
    label: "a vector account's SYSTEM PDA (signs-as 1) approves via [Advance, Passthrough], clear-signed by verify_proposal_cpi",
    shape: "[Advance, Passthrough(signs as system PDA){assert_account_hash(multisig), verify_proposal_cpi, proposal_approve}]",
    signers: [signerB], p: honestB, decoys: [decoyB],
  });

  // --- 9. C: two signers in one Passthrough, one of them the member ---------------
  await runHonest({
    name: "multi-1",
    label: "two signers [C, A] in one Advance + Passthrough, only A (second) is the Squads member",
    shape: "[Advance{C, A}, Passthrough(signers C, A){assert_account_hash(multisig), verify_proposal_cpi(#4), approve #4}]",
    signers: [signerC, signerA], p: multi1A, decoys: [decoyA],
  });
  await runHonest({
    name: "multi-2",
    label: "two signers [A, C] in one Advance + Passthrough, only A (first) is the Squads member",
    shape: "[Advance{A, C}, Passthrough(signers A, C){assert_account_hash(multisig), verify_proposal_cpi(#5), approve #5}]",
    signers: [signerA, signerC], p: multi2A, decoys: [decoyA],
  });

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
