#!/usr/bin/env node
/**
 * End-to-end: a Squads v4 vote cast by an **ed25519 programmatic signer** (EPS)
 * and clear-signed with `verify_proposal_cpi`, on a LOCAL fork only (surfpool
 * forking devnet, which has Squads v4 and the three EPS programs).
 *
 * The Squads member is a PDA of the EPS signer program
 * (`["programmatic-signer", authority]`); it can only sign inside a CPI:
 *
 *   relay tx (v1, fee payer = e2e wallet, the only transaction signature)
 *   └─ Ed25519 Signer `Submit`            data: 0x00 | sig count | 0x01 sig[64] | AUTHORIZATION MESSAGE
 *      └─ Message Executor `Execute`      data: 0x00 | EXECUTION MESSAGE          (PDA promoted to signer)
 *         ├─ Nonce `Advance`              (replay protection; nonce authority = the PDA)
 *         ├─ assert_account_hash(multisig account, owner Squads)
 *         ├─ verify_proposal_cpi(args from chain)       accounts: proposal, transaction, instructions sysvar, member
 *         └─ Squads proposal_approve(multisig, member = PDA, proposal)
 *
 * Both messages are Solana v1 messages (0x81 prefix). The authorization
 * message has exactly one instruction (the Execute), a zero lifetime, and is
 * what the cold authority key signs (raw ed25519 over the message bytes). The
 * execution message's lifetime is the current value of the EPS nonce account;
 * it is the tail of the Execute data, which is the tail of the authorization
 * message, which is the tail of the Submit data. `verify_proposal_cpi` takes
 * no location: it reads the top-level `Submit` from the instructions sysvar,
 * walks that framing to the execution message, and requires it to contain
 * this exact invocation and otherwise only clear-signing instructions plus
 * the expected vote `[multisig, member, proposal]`.
 *
 * Flow:
 *   1. generate an ed25519 authority, derive its programmatic-signer PDA
 *   2. create a Squads v4 multisig, threshold 1: the PDA is the only voter, the
 *      e2e wallet may only initiate/execute; fund vault 0; create vault
 *      transaction #1 (0.001 SOL transfer) + proposal, and a second one, #2
 *   3. create an EPS nonce account whose authority is the PDA
 *   4. expected-failure cases, each recorded on-chain (skipPreflight) with the
 *      exact custom error raised by the clear-signing program, no vote on
 *      either proposal, nonce not consumed:
 *        a. tampered expected data in the verify args      -> DataMismatch (6020)
 *        b. #1 verified, vote cast on #2                   -> VoteProposalMismatch
 *        c. extra instruction of another program (SPL Memo,
 *           else a 0-lamport System transfer)              -> ForbiddenInstruction
 *        d. top-level-only `verify_proposal` in place of
 *           `verify_proposal_cpi`                          -> must fail; the code is reported
 *           (observed: ForbiddenInstruction — it applies the top-level shape
 *           rule to the relay transaction, whose only instruction is `Submit`)
 *        e. verify_proposal_cpi as a top-level instruction,
 *           wallet as member                               -> NotInvokedViaCpi (6048)
 *   5. expected-success case: must succeed; proposal #1 lists the PDA in
 *      `approved`; prints compute units, size and the transaction version
 *
 * Requirements: a local surfpool devnet fork with the clear-signing program
 * upgraded in place to the local build:
 *   surfpool start --network devnet --no-tui --no-deploy --no-studio -y -p 8899 -w 8900
 *   solana airdrop 100 -u http://127.0.0.1:8899 -k keys/e2e-wallet.json
 *   solana program extend <program id> 60000 -u http://127.0.0.1:8899 -k keys/e2e-wallet.json
 *   solana program deploy target/deploy/squads_clear_signing.so \
 *     --program-id target/deploy/squads_clear_signing-keypair.json -u http://127.0.0.1:8899 -k keys/e2e-wallet.json
 * Refuses to run against a non-local RPC. Exits non-zero if any case fails.
 *
 * Env:
 *   RPC_URL  target cluster (default http://127.0.0.1:8899; must be local)
 *   WALLET   keypair path (default keys/e2e-wallet.json)
 */
const fs = require("fs");
const path = require("path");
const bs58 = (() => { const m = require("bs58"); return m.default ?? m; })();
const { ed25519 } = require("@noble/curves/ed25519");
const {
  Connection, Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction,
  TransactionMessage, SYSVAR_INSTRUCTIONS_PUBKEY, LAMPORTS_PER_SOL,
} = require("@solana/web3.js");
const multisig = require("@sqds/multisig");
const anchor = require("@anchor-lang/core");
const kit = require("@solana/kit");
const { sha256Hex } = require("./program-hash.cjs");

const ROOT = path.join(__dirname, "..");
const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8899";
const WALLET_PATH = process.env.WALLET || path.join(ROOT, "keys", "e2e-wallet.json");
const IDL = JSON.parse(fs.readFileSync(path.join(ROOT, "idl", "squads_clear_signing.json")));
const IS_LOCAL = (() => {
  try { return ["127.0.0.1", "localhost", "[::1]"].includes(new URL(RPC_URL).hostname); } catch { return false; }
})();
const POLL_MS = 400;

const EPS_SIGNER = new PublicKey("EdSigVfK1DkeMrjFNDMjwfQaJPhPTtX7jW8uPv3oKEgN");
const EPS_EXECUTOR = new PublicKey("ExecxgyHYsAXB4c5dZodV1zJZ9hqfsDCYkRDRATrpkFR");
const EPS_NONCE = new PublicKey("Noncediea1fH12usShuQAz28UhgAeuE5Maf32LsMUQB");
const SLOT_HASHES = new PublicKey("SysvarS1otHashes111111111111111111111111111");
const MEMO = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
const NONCE_LEN = 72; // nonce [32] | authority [32] | initialize_slot u64
const [TRANSITION_SIGNER] = PublicKey.findProgramAddressSync([Buffer.from("transition-signer")], EPS_EXECUTOR);

const V1_PREFIX = 0x81;
const V1_FIXED = 42; // prefix, 3-byte header, u32 config mask, 32-byte lifetime, ix count, address count
const LEGACY_LIMIT = 1232;
const V1_LIMIT = 4096;

const ok = (m) => console.log(`\x1b[32m✔\x1b[0m ${m}`);
const info = (m) => console.log(`  ${m}`);
const step = (m) => console.log(`\n\x1b[36m▶ ${m}\x1b[0m`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const J = (o) => JSON.stringify(o, (k, v) => (typeof v === "bigint" ? Number(v) : v));

// --- Solana v1 message (SIMD-0385), as embedded by EPS ----------------------

/**
 * Compile instructions into a v1 message with an empty config.
 * Key order: signers (the first is always writable — every message needs one
 * writable signer), writable non-signers, then readonly non-signers with the
 * invoked programs first. For the authorization message this reproduces the
 * layout of `spl_ed25519_signer_client::message::authorization_message`.
 * Signer privilege comes from `signers` only, never from instruction metas.
 */
function compileV1({ signers, instructions, lifetime }) {
  const entries = new Map(); // base58 -> { pubkey, signer, writable, program }
  const touch = (pubkey) => {
    const k = pubkey.toBase58();
    if (!entries.has(k)) entries.set(k, { pubkey, signer: false, writable: false, program: false });
    return entries.get(k);
  };
  signers.forEach((s, i) => { const e = touch(s); e.signer = true; e.writable ||= i === 0; });
  for (const ix of instructions) for (const m of ix.keys) touch(m.pubkey).writable ||= m.isWritable;
  for (const ix of instructions) touch(ix.programId).program = true;

  const all = [...entries.values()];
  const writableSigners = all.filter((e) => e.signer && e.writable);
  const readonlySigners = all.filter((e) => e.signer && !e.writable);
  const writable = all.filter((e) => !e.signer && e.writable);
  const readonly = all.filter((e) => !e.signer && !e.writable);
  const readonlyOrdered = [...readonly.filter((e) => e.program), ...readonly.filter((e) => !e.program)];
  const ordered = [...writableSigners, ...readonlySigners, ...writable, ...readonlyOrdered];
  const keys = ordered.map((e) => e.pubkey);
  const indexOf = (pubkey) => {
    const i = keys.findIndex((k) => k.equals(pubkey));
    if (i < 0) throw new Error(`key ${pubkey.toBase58()} missing from message`);
    return i;
  };
  const numSigners = writableSigners.length + readonlySigners.length;

  const headers = [];
  const payloads = [];
  for (const ix of instructions) {
    const programIndex = indexOf(ix.programId);
    if (programIndex === 0) throw new Error("a program cannot be the first (fee payer) key");
    const len = Buffer.alloc(2);
    len.writeUInt16LE(ix.data.length);
    headers.push(Buffer.from([programIndex, ix.keys.length]), len);
    payloads.push(Buffer.from(ix.keys.map((m) => indexOf(m.pubkey))), Buffer.from(ix.data));
  }
  const bytes = Buffer.concat([
    Buffer.from([V1_PREFIX, numSigners, readonlySigners.length, readonly.length]),
    Buffer.alloc(4), // config mask: none
    Buffer.from(lifetime),
    Buffer.from([instructions.length, keys.length]),
    ...keys.map((k) => k.toBuffer()),
    ...headers,
    ...payloads,
  ]);
  if (bytes[0] !== V1_PREFIX || lifetime.length !== 32) throw new Error("bad v1 message");
  return {
    bytes,
    keys,
    isSigner: (i) => i < numSigners,
    isWritable: (i) => ordered[i].writable,
  };
}

/** Message Executor `Execute`, as `spl_message_executor_client::instruction::execute`. */
function executeIx({ nonceAccount, nonceAuthority, executionMessage }) {
  return new TransactionInstruction({
    programId: EPS_EXECUTOR,
    keys: [
      { pubkey: nonceAuthority, isSigner: true, isWritable: false },
      { pubkey: nonceAccount, isSigner: false, isWritable: true },
      { pubkey: EPS_NONCE, isSigner: false, isWritable: false },
      { pubkey: TRANSITION_SIGNER, isSigner: false, isWritable: false },
      ...executionMessage.keys.map((pubkey, i) => ({
        pubkey, isSigner: executionMessage.isSigner(i), isWritable: executionMessage.isWritable(i),
      })),
    ],
    data: Buffer.concat([Buffer.from([0]), executionMessage.bytes]),
  });
}

/** Ed25519 Signer `Submit`, as `spl_ed25519_signer_client::instruction::submit`. */
function submitIx({ authorizationMessage, signatures }) {
  return new TransactionInstruction({
    programId: EPS_SIGNER,
    keys: authorizationMessage.keys.map((pubkey, i) => ({
      pubkey, isSigner: false, isWritable: authorizationMessage.isWritable(i),
    })),
    data: Buffer.concat([
      Buffer.from([0, signatures.length]),
      ...signatures.map((s) => Buffer.concat([Buffer.from([1]), Buffer.from(s)])),
      authorizationMessage.bytes,
    ]),
  });
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

const shortVecLen = (n) => (n < 0x80 ? 1 : n < 0x4000 ? 2 : 3);

/** Sizes the same single-instruction relay would have as a legacy tx, and as
 *  a v0 tx with every key except the fee payer and the program in an ALT. */
function smallerVersionSizes(ix, feePayer) {
  const unique = new Set([feePayer.toBase58(), ix.programId.toBase58(), ...ix.keys.map((k) => k.pubkey.toBase58())]);
  const ixBody = (n) => 1 + shortVecLen(n) + n + shortVecLen(ix.data.length) + ix.data.length;
  const legacy = 1 + 64 + 3 + shortVecLen(unique.size) + 32 * unique.size + 32 + 1 + ixBody(ix.keys.length);
  const looked = unique.size - 2;
  const v0 = 1 + 64 + 1 + 3 + 1 + 32 * 2 + 32 + 1 + ixBody(ix.keys.length) + 1 + (32 + 1 + 1 + looked);
  return { legacy, v0 };
}

async function main() {
  if (!IS_LOCAL) {
    throw new Error(`refusing to run against ${RPC_URL}: this test only targets a local surfpool fork`);
  }
  const connection = new Connection(RPC_URL, "confirmed");
  const rpc = kit.createSolanaRpc(RPC_URL);
  const secret = Uint8Array.from(JSON.parse(fs.readFileSync(WALLET_PATH)));
  const wallet = Keypair.fromSecretKey(secret);
  const walletSigner = await kit.createKeyPairSignerFromBytes(secret);
  console.log(`cluster: ${RPC_URL}`);
  console.log(`wallet:  ${wallet.publicKey.toBase58()}`);

  if ((await connection.getBalance(wallet.publicKey)) < 2 * LAMPORTS_PER_SOL) {
    step("airdropping 20 SOL (local cluster)");
    const sig = await connection.requestAirdrop(wallet.publicKey, 20 * LAMPORTS_PER_SOL);
    await connection.confirmTransaction(sig, "confirmed");
  }

  const programId = new PublicKey(IDL.address);
  for (const [name, id] of [
    ["squads_clear_signing", programId], ["Squads v4", multisig.PROGRAM_ID], ["EPS signer", EPS_SIGNER],
    ["EPS executor", EPS_EXECUTOR], ["EPS nonce", EPS_NONCE],
  ]) {
    const acct = await connection.getAccountInfo(id);
    if (!acct?.executable) throw new Error(`${name} program ${id.toBase58()} not found on this cluster`);
  }
  ok("clear-signing, Squads v4 and EPS signer/executor/nonce programs present");
  const hasMemo = !!(await connection.getAccountInfo(MEMO))?.executable;

  const provider = new anchor.AnchorProvider(connection, new anchor.Wallet(wallet), { commitment: "confirmed" });
  const program = new anchor.Program(IDL, provider);
  const errorCode = (name) => {
    const e = IDL.errors.find((x) => x.name === name);
    if (!e) throw new Error(`error ${name} not in IDL`);
    return e.code;
  };

  // --- senders ---------------------------------------------------------------
  const confirm = async (sig) => {
    for (let i = 0; i < 150; i++) {
      const st = (await connection.getSignatureStatuses([sig])).value[0];
      if (st && (st.confirmationStatus === "confirmed" || st.confirmationStatus === "finalized")) return st.err;
      await sleep(POLL_MS);
    }
    throw new Error(`timed out confirming ${sig}`);
  };
  const fetchMeta = async (sig) => {
    for (let i = 0; i < 20; i++) {
      const tx = await rpc.getTransaction(sig, {
        maxSupportedTransactionVersion: 1, encoding: "base64", commitment: "confirmed",
      }).send().catch(() => null);
      if (tx?.meta) return tx.meta;
      await sleep(POLL_MS);
    }
    throw new Error(`could not fetch transaction ${sig}`);
  };
  /** Legacy transaction (setup, and the top-level negative case). */
  const sendLegacy = async (instructions, signers, { skipPreflight = false } = {}) => {
    const { blockhash } = await connection.getLatestBlockhash("confirmed");
    const tx = new Transaction().add(...instructions);
    tx.recentBlockhash = blockhash;
    tx.feePayer = signers[0].publicKey;
    tx.sign(...signers);
    const sig = bs58.encode(tx.signature);
    await connection.sendRawTransaction(tx.serialize(), { skipPreflight, maxRetries: 5 });
    return { sig, err: await confirm(sig), size: tx.serialize().length };
  };
  const setup = async (label, instructions, signers) => {
    const res = await sendLegacy(instructions, signers);
    if (res.err) throw new Error(`${label} failed: ${J(res.err)} (${res.sig})`);
    return res;
  };
  /** v1 transaction (4096-byte limit), fee payer = wallet, always skipPreflight
   *  so failures are recorded on-chain. */
  const sendV1 = async (instructions) => {
    const { value: latest } = await rpc.getLatestBlockhash({ commitment: "confirmed" }).send();
    let message = kit.pipe(
      kit.createTransactionMessage({ version: 1 }),
      (m) => kit.setTransactionMessageFeePayerSigner(walletSigner, m),
      (m) => kit.setTransactionMessageLifetimeUsingBlockhash(latest, m),
      (m) => kit.setTransactionMessageComputeUnitLimit(400_000, m),
      (m) => kit.setTransactionMessageLoadedAccountsDataSizeLimit(10_000_000, m),
    );
    for (const ix of instructions) message = kit.appendTransactionMessageInstruction(toKitIx(ix), message);
    const signed = await kit.signTransactionMessageWithSigners(message);
    const wire = kit.getBase64EncodedWireTransaction(signed);
    const sig = kit.getSignatureFromTransaction(signed);
    await rpc.sendTransaction(wire, { encoding: "base64", skipPreflight: true }).send();
    return { sig, err: await confirm(sig), size: Buffer.from(wire, "base64").length };
  };

  // --- 1. the programmatic signer ---------------------------------------------
  step("generating an ed25519 authority and deriving its programmatic-signer PDA");
  const authority = Keypair.generate();
  const [memberPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("programmatic-signer"), authority.publicKey.toBuffer()], EPS_SIGNER,
  );
  ok(`authority (cold key): ${authority.publicKey.toBase58()}`);
  ok(`member (PDA):         ${memberPda.toBase58()}`);
  const signAuthorization = (bytes) => ed25519.sign(bytes, authority.secretKey.subarray(0, 32));

  // --- 2. multisig, vault transaction #1, decoy #2 ----------------------------
  step("creating Squads v4 multisig (threshold 1; PDA = only voter, wallet = initiate + execute)");
  const { Permission, Permissions } = multisig.types;
  const createKey = Keypair.generate();
  const [multisigPda] = multisig.getMultisigPda({ createKey: createKey.publicKey });
  const [programConfigPda] = multisig.getProgramConfigPda({});
  const programConfig = await multisig.accounts.ProgramConfig.fromAccountAddress(connection, programConfigPda);
  await setup("multisig create", [multisig.instructions.multisigCreateV2({
    createKey: createKey.publicKey,
    creator: wallet.publicKey,
    multisigPda,
    configAuthority: null,
    timeLock: 0,
    members: [
      { key: memberPda, permissions: Permissions.fromPermissions([Permission.Vote]) },
      { key: wallet.publicKey, permissions: Permissions.fromPermissions([Permission.Initiate, Permission.Execute]) },
    ],
    threshold: 1,
    treasury: programConfig.treasury,
    rentCollector: null,
  })], [wallet, createKey]);
  ok(`multisig: ${multisigPda.toBase58()}`);

  const [vaultPda] = multisig.getVaultPda({ multisigPda, index: 0 });
  await setup("vault funding", [SystemProgram.transfer({
    fromPubkey: wallet.publicKey, toPubkey: vaultPda, lamports: 0.2 * LAMPORTS_PER_SOL,
  })], [wallet]);

  const createProposal = async (index, to, lamports) => {
    const { blockhash } = await connection.getLatestBlockhash();
    const transactionMessage = new TransactionMessage({
      payerKey: vaultPda,
      recentBlockhash: blockhash,
      instructions: [SystemProgram.transfer({ fromPubkey: vaultPda, toPubkey: to, lamports })],
    });
    await setup(`vault transaction #${index}`, [
      multisig.instructions.vaultTransactionCreate({
        multisigPda, transactionIndex: index, creator: wallet.publicKey,
        vaultIndex: 0, ephemeralSigners: 0, transactionMessage,
      }),
      multisig.instructions.proposalCreate({ multisigPda, transactionIndex: index, creator: wallet.publicKey }),
    ], [wallet]);
    return {
      index,
      transaction: multisig.getTransactionPda({ multisigPda, index })[0],
      proposal: multisig.getProposalPda({ multisigPda, transactionIndex: index })[0],
    };
  };
  const honest = await createProposal(1n, wallet.publicKey, 0.001 * LAMPORTS_PER_SOL);
  const second = await createProposal(2n, Keypair.generate().publicKey, 0.1 * LAMPORTS_PER_SOL);
  ok(`proposal #1 (0.001 SOL vault -> wallet): ${honest.proposal.toBase58()}`);
  ok(`proposal #2 (0.1 SOL vault -> other):    ${second.proposal.toBase58()}`);

  // --- 3. EPS nonce account (authority = the PDA) ------------------------------
  step("creating the EPS nonce account (nonce authority = the programmatic signer)");
  const nonceKeypair = Keypair.generate();
  await setup("nonce create", [
    SystemProgram.createAccount({
      fromPubkey: wallet.publicKey,
      newAccountPubkey: nonceKeypair.publicKey,
      lamports: await connection.getMinimumBalanceForRentExemption(NONCE_LEN),
      space: NONCE_LEN,
      programId: EPS_NONCE,
    }),
    new TransactionInstruction({ // Nonce `Initialize`
      programId: EPS_NONCE,
      keys: [
        { pubkey: nonceKeypair.publicKey, isSigner: false, isWritable: true },
        { pubkey: memberPda, isSigner: false, isWritable: false },
        { pubkey: SLOT_HASHES, isSigner: false, isWritable: false },
      ],
      data: Buffer.from([0]),
    }),
  ], [wallet, nonceKeypair]);
  const readNonce = async () => {
    const acct = await connection.getAccountInfo(nonceKeypair.publicKey);
    if (!acct || !acct.owner.equals(EPS_NONCE) || acct.data.length !== NONCE_LEN) throw new Error("bad nonce account");
    if (!new PublicKey(acct.data.subarray(32, 64)).equals(memberPda)) throw new Error("nonce authority is not the PDA");
    return Buffer.from(acct.data.subarray(0, 32));
  };
  ok(`nonce account: ${nonceKeypair.publicKey.toBase58()} (value ${bs58.encode(await readNonce())})`);

  // --- inner instructions ------------------------------------------------------
  /** Expand the stored message into ExpectedInstruction[] (no ALTs here). */
  const buildExpected = (message) => {
    if (message.addressTableLookups.length > 0) throw new Error("unexpected lookup tables");
    const keys = message.accountKeys;
    const isSigner = (i) => i < message.numSigners;
    const isWritable = (i) => i < message.numWritableSigners
      || (i >= message.numSigners && i - message.numSigners < message.numWritableNonSigners);
    return message.instructions.map((ix) => ({
      programId: keys[ix.programIdIndex],
      accounts: Array.from(ix.accountIndexes).map((i) => ({
        pubkey: keys[i], isSigner: isSigner(i), isWritable: isWritable(i),
      })),
      data: Buffer.from(ix.data),
    }));
  };
  const vaultTx = await multisig.accounts.VaultTransaction.fromAccountAddress(connection, honest.transaction);
  const expected = buildExpected(vaultTx.message);
  const verifyArgs = (instructions, member = memberPda) => ({
    multisig: multisigPda,
    transactionIndex: new anchor.BN(honest.index.toString()),
    vaultIndex: vaultTx.vaultIndex,
    numEphemeralSigners: vaultTx.ephemeralSignerBumps.length,
    member,
    action: { approve: {} },
    instructions,
  });
  const verifyCpiIx = ({ instructions = expected, member = memberPda } = {}) => program.methods
    .verifyProposalCpi(verifyArgs(instructions, member))
    .accounts({
      proposal: honest.proposal, transaction: honest.transaction,
      instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY, member,
    })
    .instruction();
  const verifyTopLevelIx = () => program.methods
    .verifyProposal(verifyArgs(expected))
    .accounts({
      proposal: honest.proposal, transaction: honest.transaction, instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
    })
    .instruction();
  const multisigInfo = await connection.getAccountInfo(multisigPda);
  const assertMultisigIx = await program.methods
    .assertAccountHash({ account: multisigPda, owner: multisig.PROGRAM_ID, expectedHash: sha256Hex(multisigInfo.data) })
    .accounts({ account: multisigPda })
    .instruction();
  const approveIx = (index) => multisig.instructions.proposalApprove({
    multisigPda, transactionIndex: index, member: memberPda,
  });
  // An instruction of a program the shape rule does not allow.
  const foreign = hasMemo
    ? { name: "SPL Memo", program: MEMO,
        ix: new TransactionInstruction({ programId: MEMO, keys: [], data: Buffer.from("smuggled") }) }
    : { name: "System transfer of 0 lamports", program: SystemProgram.programId,
        ix: SystemProgram.transfer({ fromPubkey: memberPda, toPubkey: wallet.publicKey, lamports: 0 }) };

  // --- the EPS envelope ---------------------------------------------------------
  /**
   * Walk a `Submit`'s data the way the signer program deserializes it and
   * return the execution message — an independent check of the envelope this
   * script builds (single authority, zero config masks).
   */
  const executionMessageOf = (data) => {
    let o = 2;
    if (data[0] !== 0) throw new Error("not a Submit");
    for (let i = 0; i < data[1]; i++) o += data[o] === 1 ? 65 : 1;
    if (data[o] !== V1_PREFIX || data[o + 40] !== 1) throw new Error("bad authorization message");
    const table = o + V1_FIXED;
    const header = table + 32 * data[o + 41];
    const program = new PublicKey(data.subarray(table + 32 * data[header], table + 32 * data[header] + 32));
    const executeData = data.subarray(header + 4 + data[header + 1]);
    if (!program.equals(EPS_EXECUTOR) || executeData.length !== data.readUInt16LE(header + 2) || executeData[0] !== 0) {
      throw new Error("the authorization message's instruction is not an Execute");
    }
    return executeData.subarray(1);
  };

  /**
   * Build the top-level `Submit` for the inner instructions: execution message
   * (lifetime = current nonce, signer = the PDA) -> Execute -> authorization
   * message (signer = authority) -> signature -> Submit.
   */
  const buildSubmit = async (inner) => {
    const executionMessage = compileV1({ signers: [memberPda], instructions: inner, lifetime: await readNonce() });
    const execute = executeIx({ nonceAccount: nonceKeypair.publicKey, nonceAuthority: memberPda, executionMessage });
    const authorizationMessage = compileV1({
      signers: [authority.publicKey], instructions: [execute], lifetime: Buffer.alloc(32),
    });
    const submit = submitIx({
      authorizationMessage, signatures: [signAuthorization(authorizationMessage.bytes)],
    });
    if (!executionMessageOf(submit.data).equals(executionMessage.bytes)) throw new Error("envelope self-check failed");
    return { executionMessage, execute, authorizationMessage, submit };
  };

  const fetchProposal = (p) => multisig.accounts.Proposal.fromAccountAddress(connection, p);
  const votes = async () => (await fetchProposal(honest.proposal)).approved.length
    + (await fetchProposal(second.proposal)).approved.length;
  const errorLogs = (meta) => (meta.logMessages || []).filter((l) => /Error|forbidden|mismatch|failed/i.test(l));

  // --- 4. expected-failure cases --------------------------------------------------
  const tampered = expected.map((ix) => ({ ...ix, data: Buffer.from(ix.data) }));
  tampered[0].data[4] ^= 0xff; // corrupt the u64 lamports of the transfer
  if (tampered[0].data.equals(expected[0].data)) throw new Error("tampering had no effect");
  const honestInner = async () => [assertMultisigIx, await verifyCpiIx(), approveIx(honest.index)];
  const viaEps = async (inner) => sendV1([(await buildSubmit(inner)).submit]);

  const negatives = [
    {
      id: "a", label: "expected instruction data differs from the stored vault transaction", expect: "DataMismatch",
      send: async () => viaEps([assertMultisigIx, await verifyCpiIx({ instructions: tampered }), approveIx(honest.index)]),
    },
    {
      id: "b", label: "proposal #1 verified, vote cast on proposal #2", expect: "VoteProposalMismatch",
      send: async () => viaEps([assertMultisigIx, await verifyCpiIx(), approveIx(second.index)]),
    },
    {
      id: "c", label: `extra instruction of another program (${foreign.name}) in the execution message`,
      expect: "ForbiddenInstruction", log: `forbidden program ${foreign.program.toBase58()}`,
      send: async () => viaEps([...(await honestInner()), foreign.ix]),
    },
    {
      // No code is prescribed: the case must fail in the clear-signing program
      // and the code is reported.
      id: "d", label: "top-level-only verify_proposal in place of verify_proposal_cpi", expect: null,
      send: async () => viaEps([assertMultisigIx, await verifyTopLevelIx(), approveIx(honest.index)]),
    },
    {
      id: "e", label: "verify_proposal_cpi as a top-level instruction, wallet as member", expect: "NotInvokedViaCpi",
      send: async () => sendLegacy([await verifyCpiIx({ member: wallet.publicKey })], [wallet], { skipPreflight: true }),
    },
  ];
  if (errorCode("DataMismatch") !== 6020 || errorCode("NotInvokedViaCpi") !== 6048) {
    throw new Error("IDL error codes moved: DataMismatch must be 6020 and NotInvokedViaCpi 6048");
  }
  const errorName = (code) => IDL.errors.find((x) => x.code === code)?.name;

  const results = [];
  const record = (id, label, pass, detail) => {
    results.push({ id, label, pass, detail });
    console.log(`${pass ? "\x1b[32mPASS" : "\x1b[31mFAIL"}\x1b[0m [${id}] ${label} — ${detail}`);
  };

  for (const c of negatives) {
    step(`case ${c.id}: ${c.label} — must fail with ${c.expect ? `${c.expect} (${errorCode(c.expect)})` : "a clear-signing error"}`);
    try {
      const nonceBefore = await readNonce();
      const res = await c.send();
      const meta = await fetchMeta(res.sig);
      const logs = meta.logMessages || [];
      errorLogs(meta).forEach((l) => info(l));
      info(`tx ${res.sig} (${res.size} bytes) err ${J(res.err)}`);
      const [index, inner] = res.err?.InstructionError ?? [];
      const code = inner?.Custom === undefined ? undefined : Number(inner.Custom);
      const problems = [];
      if (Number(index) !== 0 || code === undefined) {
        problems.push(`expected InstructionError[0, Custom(..)], got ${J(res.err)}`);
      } else if (c.expect && code !== errorCode(c.expect)) {
        problems.push(`expected Custom(${errorCode(c.expect)}) ${c.expect}, got Custom(${code}) ${errorName(code) ?? "?"}`);
      } else if (!errorName(code)) {
        problems.push(`Custom(${code}) is not a clear-signing error`);
      }
      // The code must come from the clear-signing program, not from a
      // look-alike number of another program in the CPI chain.
      const raised = `Program ${programId.toBase58()} failed: custom program error: 0x${(code ?? 0).toString(16)}`;
      if (!logs.some((l) => l.includes(raised))) problems.push("the error was not raised by the clear-signing program");
      if (c.log && !logs.some((l) => l.includes(c.log))) problems.push(`log "${c.log}" missing`);
      if ((await votes()) !== 0) problems.push("a vote was recorded");
      if (!(await readNonce()).equals(nonceBefore)) problems.push("the nonce was consumed");
      record(c.id, c.label, problems.length === 0, problems.length
        ? problems.join("; ")
        : `rejected on-chain with ${errorName(code)} (${code}); no vote on either proposal, nonce intact`);
    } catch (e) {
      record(c.id, c.label, false, `threw: ${e.message || e}`);
    }
  }

  // --- 5. honest case --------------------------------------------------------------
  step("case success: [assert_account_hash(multisig), verify_proposal_cpi(chain truth), proposal_approve] via EPS — must succeed");
  try {
    const nonceBefore = await readNonce();
    const built = await buildSubmit(await honestInner());
    const sizes = smallerVersionSizes(built.submit, wallet.publicKey);
    info(`execution message:     ${built.executionMessage.bytes.length} bytes, ${built.executionMessage.keys.length} keys`);
    info(`authorization message: ${built.authorizationMessage.bytes.length} bytes, ${built.authorizationMessage.keys.length} keys (signed by the authority)`);
    info(`Submit data:           ${built.submit.data.length} bytes, ${built.submit.keys.length} accounts`);
    const res = await sendV1([built.submit]);
    const meta = await fetchMeta(res.sig);
    if (res.err) {
      (meta.logMessages || []).forEach((l) => info(l));
      throw new Error(`transaction failed: ${J(res.err)} (${res.sig})`);
    }
    (meta.logMessages || []).filter((l) => /clear-signing OK|account hash OK/.test(l)).forEach((l) => info(l));
    const proposal = await fetchProposal(honest.proposal);
    const problems = [];
    if (!proposal.approved.some((k) => k.equals(memberPda))) problems.push("PDA not in proposal.approved");
    if (proposal.approved.length !== 1) problems.push(`expected exactly 1 approval, got ${proposal.approved.length}`);
    if (proposal.status.__kind !== "Approved") problems.push(`proposal status is ${proposal.status.__kind}`);
    if ((await fetchProposal(second.proposal)).approved.length !== 0) problems.push("proposal #2 got a vote");
    if ((await readNonce()).equals(nonceBefore)) problems.push("nonce was not advanced");
    for (const want of ["account hash OK", "clear-signing OK (cpi)"]) {
      if (!(meta.logMessages || []).some((l) => l.includes(want))) problems.push(`log "${want}" missing`);
    }
    info(`tx ${res.sig}`);
    info(`compute units consumed: ${Number(meta.computeUnitsConsumed)}`);
    info(`transaction size:       ${res.size} bytes, version 1 (limit ${V1_LIMIT})`);
    info(`why v1: the same relay is ${sizes.legacy} bytes as a legacy tx and ${sizes.v0} bytes as v0 with every `
      + `account in an address lookup table (limit ${LEGACY_LIMIT}); the Submit data alone is ${built.submit.data.length} bytes, `
      + `because the authorization message repeats every account key inline`);
    if (sizes.v0 <= LEGACY_LIMIT) problems.push("v0 + ALT would have fit; the v1 claim is wrong");
    record("success", "clear-signed approval by the programmatic signer", problems.length === 0, problems.length
      ? problems.join("; ")
      : `approved by ${memberPda.toBase58()}, status ${proposal.status.__kind}; `
        + `${Number(meta.computeUnitsConsumed)} CU, ${res.size} bytes (v1)`);
  } catch (e) {
    record("success", "clear-signed approval by the programmatic signer", false, `threw: ${e.message || e}`);
  }

  // --- summary -----------------------------------------------------------------------
  const failed = results.filter((r) => !r.pass);
  console.log(`\nsummary: ${results.length - failed.length}/${results.length} cases passed`);
  if (failed.length) {
    console.log(`\x1b[31mE2E-EPS FAILED\x1b[0m — ${failed.map((r) => r.id).join(", ")}`);
    process.exit(1);
  }
  console.log("\x1b[32mE2E-EPS PASSED\x1b[0m — programmatic-signer vote clear-signed via verify_proposal_cpi; every expected failure rejected on-chain.");
}

main().catch((e) => { console.error("\n\x1b[31mE2E-EPS FAILED:\x1b[0m", e); process.exit(1); });
