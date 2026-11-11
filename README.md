# Squads Clear Signing

A companion program for [Squads Protocol v4](https://github.com/Squads-Protocol/v4) that makes
proposal approvals **clear-signable on offline / air-gapped signing devices**: the signer sees
exactly what a proposal will do, and the chain rejects the vote if what they saw isn't what the
proposal actually does.

Program ID: `7xs3LhQjKoCGfXm2qst7LUhismrG1bGxz5Jw6AHij7eu` *(placeholder — regenerate before any real deployment)*

![Signing maturity ladder](docs/img/signing-ladder.svg)

---

## The problem

When a Squads member approves a proposal, the transaction they sign contains only
`proposal_approve(multisig, member, proposal)` — a vote on a PDA. The *content* being approved
(the `VaultTransaction`) lives on-chain, where an offline device cannot see it. A device that
decodes transactions purely from **IDL + instruction data** can only show *"approve proposal
#42"*, never *what* #42 does. That is blind signing: a compromised coordinator machine can show
the signer one thing while the on-chain proposal does another.

Clear signing alone doesn't fix this for Squads, because the vote *is* fully decoded — it just
doesn't contain anything worth reading. Where the content lives decides how far each signing
setup can get:

| Track | Stage 1 | Stage 2 | Stage 3 |
|---|---|---|---|
| **Online wallet** (normal tx) | Blind: signs opaque bytes | **Clear**: IDL-decoded instructions | not needed — the tx *is* the content |
| **Squads — online** | Blind | Clear, but only *"approve #42"* | **Clear + chain introspection**: wallet reads the proposal over RPC |
| **Squads — offline** | Blind | Clear, no context: *"approve #42 → ???"* | **Clear signing via this program**: content inside the tx, enforced on-chain |

### Online: blind → clear

For an ordinary transaction every instruction is inside the signed payload, so decoding it via
IDL shows the whole truth.

```mermaid
sequenceDiagram
    autonumber
    participant H as Host / dApp
    participant W as Wallet
    H->>W: transaction bytes
    alt Blind signing
        W-->>W: shows hash / raw bytes
    else Clear signing
        W-->>W: decodes ixs via IDL → "Transfer 5 SOL → 9xQe…"
    end
    W->>H: signature
```

### Squads online: blind → clear → clear + chain introspection

```mermaid
sequenceDiagram
    autonumber
    participant C as Coordinator
    participant W as Member wallet (online)
    participant R as RPC
    participant S as Squads v4
    C->>W: tx = [proposal_approve(#42)]
    Note over W: Stage 2 — clear signing<br/>shows "Approve proposal #42" (nothing more)
    W->>R: getAccount(VaultTransaction PDA #42)
    R-->>W: stored message
    Note over W: Stage 3 — introspection<br/>renders "#42 → Upgrade program Abc…"
    W->>S: signed vote
```

Stage 3 works only because **the wallet itself is online**. It trusts its RPC and its own
rendering, and nothing on-chain ties the vote to what was displayed.

### Squads offline: blind → clear, no context → clear signing via this program

An air-gapped device has no RPC, so it can't introspect. Without this program it is stuck at
stage 2: it can render the vote, but not what the vote approves.

![What the offline device shows at each stage](docs/img/device-screens.svg)

---

## The fix

The wallet prepends instructions from this program to the same transaction as the vote:

```
tx = [ squads_clear_signing::verify_buffer_hash(buffer, sha256-hex),  ← program upgrades only
       squads_clear_signing::assert_*(...)*,                          ← optional state pins (below)
       squads_clear_signing::verify_proposal(expected_content),       ← decodable offline via IDL
       squads_multisig_program::proposal_approve(...) ]
```

`verify_proposal`'s arguments carry the **complete expected content** of the vault transaction —
every inner program id, every account (pubkey + signer/writable flags), and the raw instruction
data, byte for byte. All of it is structured Anchor data, so the offline device renders it from
this program's IDL alone (and can recursively decode inner `data` blobs using the inner programs'
IDLs, since the inner `program_id`s are right there).

```mermaid
sequenceDiagram
    autonumber
    participant C as Coordinator (online, untrusted)
    participant D as Offline device
    participant P as squads-clear-signing
    participant S as Squads v4
    C->>C: read VaultTransaction #42 from chain
    C->>D: tx = [verify_proposal(content), proposal_approve(#42)]
    Note over D: decodes everything from IDL alone<br/>"#42 → Upgrade Abc…, buffer sha256 7f3c…"
    D->>C: signature (signer approves what they saw)
    C->>P: submit tx
    P->>P: ① diff the voted proposal's stored tx vs args, byte for byte<br/>② tx contains only allowed ixs + this exact vote
    alt content matches
        P->>S: proposal_approve lands ✅
    else any mismatch
        P--xS: whole tx aborts, no vote recorded ❌
    end
```

### What the chain enforces

```mermaid
flowchart LR
    A[verify_proposal args<br/>what the signer saw] --> C{1 · Content diff}
    C -->|ok| D{2 · Tx shape}
    D -->|ok| E([Vote lands ✅])
    C -->|mismatch| X([Abort ❌])
    D -->|mismatch| X
    F[verify_buffer_hash<br/>sha256 of buffer == shown digest] -->|mismatch| X
```

1. **Content diff** — deserializes the `VaultTransaction` behind the voted proposal and compares its compiled
   message against `args.instructions`: program ids, account pubkeys, writable/signer flags
   (using Squads' exact header semantics: `[writable signers][ro signers][writable non-signers]
   [ro non-signers]`, then ALT-loaded writables, then ALT-loaded readonlys), and byte-exact data.
   Address-lookup-table keys are resolved through the *actual* table accounts, which must be
   passed as remaining accounts in message order. (Lookup tables are append-only, so an
   index→address mapping validated at approval time cannot change before execution.)

   The transaction is tied to the proposal without any PDA derivation: both accounts must be
   Squads-owned, carry the `Proposal` / `VaultTransaction` discriminators, and record the same
   `(multisig, index)` as each other and as the args. Squads only creates these accounts at their
   canonical addresses, so those stored fields are authoritative (and a `ConfigTransaction`/`Batch`
   at the same index is refused by the discriminator).
2. **Transaction shape** — reads the **instructions sysvar** and requires every top-level
   instruction in the outer transaction to be one of:
   - this program,
   - the Compute Budget program, or
   - a Squads v4 vote instruction whose discriminator matches `args.action` and whose accounts
     are exactly `(args.multisig, args.member as signer, the proposal passed to verify_proposal)`.

   At least one such vote must be present; **anything else aborts**. So if the transaction
   succeeds at all, the only effect it can have had is the exact vote the signer was shown.

Any mismatch → the whole transaction fails → the vote never lands.

### Program upgrades: `verify_buffer_hash`

Program-upgrade proposals are the hard case for clear signing: the vault transaction's inner
instruction is a loader-v3 `Upgrade` that only *references* a BPF buffer account by address. The
offline signer sees the buffer's pubkey but not the code it holds — a compromised coordinator can
point the proposal at a malicious buffer. `verify_proposal` binds the buffer *address*, but not
its *contents*.

`verify_buffer_hash(buffer, expected_hash)` closes that: it reads the buffer account, checks its
loader-v3 owner and `Buffer` state tag, extracts the program bytes, and hashes them with
**SHA-256 via the native `sol_sha256` syscall** over the bytes with trailing zeros trimmed — the
exact convention (and exact digest) of `solana-verify get-buffer-hash`. `expected_hash` is a
**lowercase-hex `String` (64 chars)** — not a raw byte array — so the offline device renders the
*human-readable digest* the signer compares against `solana-verify`, instead of opaque numbers.
On-chain the program hex-decodes it (rejecting wrong length / non-hex) and compares bytes. Hashing
costs about 0.5 CU per trimmed program byte (≈500k CU for a 1 MB build), so wallets should raise the
compute-unit limit on upgrade votes. Any mismatch aborts.

> Earlier iterations hashed with `brine-ed25519`, which only offers SHA-512 — a valid commitment,
> but **not** the digest `solana-verify` prints (SHA-256). Switching to the native SHA-256 syscall
> makes the displayed hash directly comparable to `solana-verify get-buffer-hash` and is ~1000× cheaper.

`verify_proposal`'s transaction-shape check whitelists this program (and the ComputeBudget program),
so the clear-signing instructions sit in the same transaction as the vote without tripping the
"nothing but the vote" rule.

### Pinning other state: `assert_account_hash` and `assert_program_revision`

`verify_proposal` binds *what the proposal does*; some proposals are only safe given *what other
accounts contain* at vote time. Two standalone assertions let the signer pin that state too. Both
take a 64-char lowercase-hex SHA-256 (`InvalidHashFormat`, 6037, otherwise) and abort on mismatch.

**`assert_account_hash({ account, owner: Option<Pubkey>, expected_hash })`** — any account
(the multisig's own config, a mint, an oracle, a program's config PDA):

1. the passed account equals `args.account` (`AssertedAccountMismatch`, 6038);
2. if `owner` is `Some`, the account's owner equals it (`AccountOwnerMismatch`, 6039) — pass it
   whenever the data is only meaningful under a specific program;
3. `sha256(account.data)` over the **raw, untrimmed** data equals `expected_hash`
   (`AccountHashMismatch`, 6040). Unlike program hashes, trailing zeros are significant for
   account state, so nothing is trimmed. Off-chain: `sha256(getAccountInfo(account).data)`.

Only data and (optionally) owner are covered — not lamports or the executable flag. A missing
account has empty data and the system program as owner, so it passes with `sha256("")` unless
`owner` excludes that.

**`assert_program_revision({ program, expected_hash })`** — the specialization for a deployed
loader-v3 program, whose code lives in a separate ProgramData account:

1. the `program` account equals `args.program` (`ProgramKeyMismatch`, 6041), is owned by the BPF
   upgradeable loader (`InvalidProgramOwner`, 6042), and is in the `Program` state (`NotAProgram`, 6043);
2. the `programdata_address` stored *in* the program account equals the passed `program_data`
   account (`ProgramDataAddressMismatch`, 6044), which is loader-owned (`InvalidProgramDataOwner`,
   6045) and in the `ProgramData` state (`NotAProgramData`, 6046);
3. the ProgramData's program bytes, trailing zeros trimmed, SHA-256 to `expected_hash`
   (`ProgramHashMismatch`, 6047) — byte-identical to `solana-verify get-program-hash <program>`.

The ProgramData metadata (deploy slot, upgrade authority) is excluded, so the digest identifies
the build, not the deployment. Typical uses: confirm the build a proposal will interact with, or
the currently deployed build before approving its upgrade.

> **Vote-time only.** Like every check in this program, both assertions hold in the vote
> transaction, not at `vault_transaction_execute`. An account can change, and a program with a live
> upgrade authority can be upgraded, between the vote and execution. Pinning is durable only for
> state that can't change afterwards (e.g. an immutable program, or one whose upgrade authority is
> this multisig's own vault).

Cost: hashing uses the `sol_sha256` syscall at about **0.5 CU per hashed byte**. For programs that's
the trimmed ELF size, not the ProgramData allocation: zero padding is skipped in 4 KB `sol_memcmp`
chunks for a few CU each. Measured: ≈112k CU for this program (210 KB), ≈517k CU for Squads v4
(980 KB ELF in a 1.47 MB ProgramData). Raise the compute-unit limit accordingly; more than about
2.5 MB of hashed bytes doesn't fit in a 1.4M CU transaction.

### Programmatic signers: `verify_proposal_cpi`

Everything above assumes the multisig member is the offline device's own key, signing the
transaction that holds the vote. A member can instead be a **programmatic signer**: a PDA of a
signer program, which signs only inside a CPI made by that program. The offline key then never
signs a Solana transaction. It signs a payload defined by the signer program (the *driver*), and
a relayer pays the fee and submits. The vote is no longer a top-level instruction, so
`verify_proposal` cannot see it in the instructions sysvar, and would reject the driver's
top-level instruction as `ForbiddenInstruction` anyway.

`verify_proposal_cpi(args: VerifyProposalArgs)` covers this case. It runs the same content diff
as `verify_proposal` (same args, same accounts plus the member, same error codes). In place of
the top-level shape check, it loads the top-level instruction this CPI descends from, recognises
the driver from it, parses that driver's framing from the first byte of the instruction data to
reach the instruction list the driver executes, and applies the shape rule to that list.

There is no location argument. A location chosen by whoever builds the payload can be aimed at
bytes that parse as a valid list but that the driver never executes: an address table, another
instruction's data, the data of a wrapping program's instruction.

Two drivers are recognised; a top-level instruction of any other program fails with
`UnsupportedSignerDriver` (6050). That includes a program that wraps a driver: the driver's
instruction must itself be top-level. Neither driver is production-ready: both are deployed on
devnet only, and the first is described by its authors as not fully audited.

**[ed25519 programmatic signer](https://github.com/solana-program/ed25519-programmatic-signer)**
(`EdSigVfK1DkeMrjFNDMjwfQaJPhPTtX7jW8uPv3oKEgN`).
The offline key ed25519-signs an *authorization message*: a Solana v1 message (SIMD-0385) with one
instruction, the Message Executor's `Execute`, whose data carries an *execution message* (another
v1 message) holding the inner instructions. `Submit` verifies the signature in-program and CPIs
`Execute` with the PDA `["programmatic-signer", authority]` as signer; the executor advances a
nonce and CPIs each inner instruction.

```
relayed tx (fee payer: relayer)
└─ Ed25519 Signer :: Submit(signatures, authorization message)       ← top level
   └─ Message Executor :: Execute(execution message)                 ← CPI, PDA signs
      ├─ squads_clear_signing::assert_*(...)*                        ← CPI, optional
      ├─ squads_clear_signing::verify_proposal_cpi(content)
      └─ squads_multisig_program::proposal_approve(member = PDA)
```

This driver is recognised by the top-level instruction's program id. The `Submit` data is walked
from byte 0 and must be consumed exactly:

- the `Submit` discriminator (`0x00`), then the signature vector: a count, then per entry `0x00`
  or `0x01` followed by a 64-byte signature;
- the authorization message: a v1 message (`0x81` prefix, zero config mask) with exactly one
  instruction, whose program is the Message Executor
  (`ExecxgyHYsAXB4c5dZodV1zJZ9hqfsDCYkRDRATrpkFR`) and whose data runs to the end of the `Submit`
  data;
- that instruction's data: the `Execute` discriminator (`0x00`), then the execution message.

The execution message is the embedded list. It is a v1 message with a zero config mask. Program
ids and accounts are indexes into its own address table, and an account is a signer iff its index
is below `num_required_signatures`, so the member PDA must be in the message's signer region.

The rest of the transaction is not restricted in this mode: the member PDA signs only inside a
`Submit`'s execution, and every `Submit` needs its own signed authorization message.

**[Vector](https://github.com/tiago18c/vector)** (`74mXFW7BSAAwc6zQC2uYKuDcWnz17HHXMWqLnEeg9BJv`,
one program for every signature scheme; branch `feat/single-program`, deployed on devnet). The
transaction is `[Advance, Passthrough]`, both top-level. The off-chain key signs a digest of the
whole transaction, which `Advance` verifies. `Passthrough` then invokes each sub-instruction,
signing as one or more vector accounts: each either as itself, PDA
`["vector", [scheme], sha256(key)]`, or as its system PDA, `[vector address]`, which is owned by
the System program. The multisig member can be either address.

```
tx = [ Vector :: Advance(signatures),                                ← top level
       Vector :: Passthrough(signers, { num_accounts, data_len, data }*) ]   ← top level
         ├─ squads_clear_signing::verify_proposal_cpi(content)
         └─ squads_multisig_program::proposal_approve(member = PDA)  ← CPIs, PDA signs
```

This driver is recognised by the top-level instruction's program id. The instruction must be a
`Passthrough` (discriminator `0x01`), and the embedded list is read from its layout:

- data: `0x01`, a signer count, one byte per signer (`0` signs as the vector account, `1` as its
  system PDA), a `count` byte, then per sub-instruction `{ num_accounts: u8, data_len: u16 LE, data }`;
- accounts: the instructions sysvar, the signers' vector accounts, then per sub-instruction its
  program followed by its `num_accounts` accounts.

The program does not look for the member among the signers. The member signs this CPI without
signing the transaction, and the CPI is made directly by the `Passthrough`, so the signature can
only come from that `Passthrough`: the member is one of the addresses it signs as. For the same
reason the member's account in the embedded vote is counted as a signer, although the top-level
account flags, which describe the transaction and not the CPI, say otherwise.

An `Advance` authorizes every later `Passthrough` in the transaction that names its accounts, so
every other top-level instruction of the Vector program must be an `Advance` (discriminator
`0x00`). A second `Passthrough` could use the member's signature outside the checked list. The
rule is an allow-list, so it also rejects harmless ones, such as an `Initialize` in the same
transaction.

#### What the chain enforces

1. **Invoked via CPI** — a top-level call fails with `NotInvokedViaCpi` (6048).
2. **The member signs** — the `member` account must sign the CPI (Anchor's `AccountNotSigner`,
   3010, otherwise) and equal `args.member` (`MemberAccountMismatch`, 6049).
3. **Content diff** — identical to `verify_proposal`.
4. **The member is a programmatic signer** — it must not be a signer of the transaction
   (`MemberIsTransactionSigner`, 6056). Both drivers forward real transaction signers into their
   CPIs, and a key that signs the transaction could also vote from any other top-level
   instruction.
5. **Driver** — the top-level instruction this CPI descends from belongs to the ed25519 signer
   program or to the Vector program (`UnsupportedSignerDriver`, 6050), and has that driver's
   layout: a `Submit` that walks exactly to an `Execute` of the Message Executor, or a
   `Passthrough` with a well-formed signer list (`MalformedDriverInstruction`, 6051).
6. **Vector siblings** — in the Vector mode, every other top-level instruction of the same
   program is an `Advance` (`ForbiddenDriverInstruction`, 6055).
7. **List framing** — the embedded list must parse: bounds, the `0x81` prefix, zero config mask,
   resolvable account indexes (`MalformedEmbeddedInstructions`, 6052). It must end exactly: an
   execution message at its last byte, a `Passthrough` list at the end of both the data and the
   account list (`EmbeddedTrailingBytes`, 6053).
8. **Contains this invocation** — one instruction in the list must target this program with data
   equal, byte for byte, to this invocation's discriminator and `args`
   (`EmbeddedSelfInstructionMissing`, 6054).
9. **Shape** — every instruction in the list is either this program's or the exact expected vote,
   with at least one vote. Compute Budget instructions are accepted at top level by
   `verify_proposal` only, not inside an embedded list. The codes are reused:
   `ForbiddenInstruction` (6022), `UnexpectedSquadsInstruction` (6023),
   `MalformedVoteInstruction` (6024), `VoteMultisigMismatch` (6025), `VoteProposalMismatch` (6026),
   `VoteMemberMismatch` (6027), `VoteMemberNotSigner` (6028), `MissingVoteInstruction` (6029).
10. **Invoked by the driver directly** — the instruction runs at the depth at which the driver
    invokes its listed instructions: 3 under the ed25519 signer, 2 under Vector
    (`UnexpectedStackHeight`, 6057).

`verify_buffer_hash`, `assert_account_hash` and `assert_program_revision` never look at the
top-level instructions, so they work unchanged when called via CPI and can sit in the embedded
list next to `verify_proposal_cpi`.

#### What the chain does not enforce

- **Other top-level instructions** that are not the Vector program's. They run without the
  member's signature, which exists only inside the driver's CPI.
- **Replay and expiry.** These belong to the driver. Both drivers use a nonce and neither has a
  built-in expiry, so a signed payload stays valid until its nonce is consumed. As everywhere in
  this program, the checks hold at vote time only.
- **Any other driver.** A member behind a different signer program cannot use this instruction.

#### Compiled-in assumptions

- The program ids of the ed25519 signer, the Message Executor and Vector, and the wire layouts of
  both drivers, are compiled into this program. A change to any of them needs an upgrade of this
  program.
- The checks rely on the deployed drivers behaving as their sources do today: `Submit` invokes
  exactly one executor instruction, the executor runs exactly the execution message, and Vector's
  `Passthrough` cannot be reached by CPI. An upgrade of a driver that changes this, or its layout,
  would silently invalidate the checks. To pin the driver's build as well, put an
  `assert_program_revision` for the driver program in the same embedded list.

### The attack it stops

| Scenario | Before (offline, stage 2) | With this program |
|---|---|---|
| Coordinator shows "upgrade to v2" but #42 points to a malicious buffer | Device shows only *"approve #42"* → signer approves ❌ | Shown hash ≠ on-chain buffer → `BufferHashMismatch` (6033), no vote ✅ |
| Coordinator shows a benign transfer, but #42 drains the vault | Signer approves blindly ❌ | Shown content ≠ stored tx → `DataMismatch` (6020), no vote ✅ |
| Coordinator shows the truth | Signer can't tell it's the truth | Device renders it; the chain confirms it ✅ |

An honest wallet builds the expected content **from the chain**, so validation passes and the
device displays the truth. A dishonest wallet must either show the device data that doesn't match
the chain (tx aborts) or show the truth (signer catches it).

---

## Trust model

- The companion program can only **abort** — it holds no authority, signs nothing, and is never
  in the CPI path of the vote itself. A bug in it can cause false rejections, never a forged
  approval beyond what the signer already signed.
- The offline device's policy must be: **only sign a transaction it can fully decode as
  `[compute budget*, verify_buffer_hash?, (assert_account_hash | assert_program_revision)*, verify_proposal, proposal_approve]`** with this
  program's known program ID, and render the args to the user. Everything else is enforced on-chain.
- With a [programmatic signer](#programmatic-signers-verify_proposal_cpi) the device signs the
  driver's payload (the authorization message, or the transaction digest), not a transaction with
  a top-level vote. Its policy is the same, applied to the embedded list it decodes from what it
  signs: **sign only if that list is
  `[verify_buffer_hash?, (assert_account_hash | assert_program_revision)*, verify_proposal_cpi, proposal_approve]`**
  with this program's known program ID. The program locates the list itself, so the device has no
  location to check. Replay protection and expiry are the driver's.
- The sysvar only exposes *top-level* instructions, which is why the shape check forbids unknown
  programs outright: a foreign instruction could otherwise CPI into Squads (with the member's
  signer privilege) invisibly.
- One vote per transaction: two `verify_proposal`s for *different* proposals in one transaction
  mutually fail each other's shape check, by design.

## What's validated vs. not

| Checked | Not checked (by design) |
|---|---|
| Proposal ↔ transaction: owner, discriminator, same `(multisig, index)` | Proposal status / threshold (Squads enforces on vote & execute) |
| `multisig`, `index`, `vault_index`, ephemeral signer count | `creator` (no post-creation authority) |
| Every instruction: program id, accounts, flags, raw data | Semantic meaning of inner data (that's the device's rendering job) |
| ALT addresses resolved via real table accounts | Lookup table liveness (a deactivated table just fails at execution) |
| Outer tx contains only allowed instructions + the exact vote | Votes on `ConfigTransaction`/`Batch` proposals (see limitations) |
| Upgrade buffer SHA-256 (when `verify_buffer_hash` is present) | |
| Raw account data SHA-256 + optional owner (when `assert_account_hash` is present) | |
| Program → ProgramData link + build SHA-256 (when `assert_program_revision` is present) | |
| `verify_proposal_cpi`: called via CPI directly by the driver, member signs, equals `args.member` and is not a transaction signer | Other top-level instructions that are not the Vector program's (`verify_proposal_cpi` only) |
| `verify_proposal_cpi`: driver identity (the ed25519 signer's or Vector's program id) and its framing down to the executed list | Replay protection and expiry of the signed payload (the driver's nonce) |
| `verify_proposal_cpi`: embedded list ends exactly, contains this invocation, holds only this program's instructions + the exact vote | Any driver other than these two (rejected), and later upgrades of the driver programs themselves |
| `verify_proposal_cpi`, Vector: every other top-level instruction of the Vector program is an `Advance` | |

## Status & limitations

- **Validated on devnet** against live Squads v4, otter-verify, and program-metadata — including
  a bundled *upgrade + verify-build + IDL* proposal: both tamper cases abort, and the honest
  approval executes the upgrade, writes the verification record, and creates the canonical IDL.
- **Transaction size** — the args duplicate the whole inner message, so the approval grows with
  the bundle. Legacy/v0 caps at 1232 bytes; larger bundles use **v1 (4 KB) transactions** (see
  [below](#larger-bundles-version-1-4-kb-transactions)). A hash-commitment mode (device hashes
  the rendered payload chunk-by-chunk) could lift the limit further.
- **Vault transactions only** — votes on `ConfigTransaction` and `Batch` proposals are not yet
  supported (the discriminator check will correctly refuse them); a `verify_config_proposal`
  twin covering `ConfigAction`s is the natural extension, and arguably even more important
  (config changes rotate keys/thresholds).
- **Programmatic signers** — `verify_proposal_cpi` supports two drivers (end-to-end tests:
  [below](#end-to-end-programmatic-signers)), and neither is production-ready: both are
  deployed on devnet only, and the ed25519 programmatic signer is not fully audited. Their wire
  layouts and program ids are compiled in, so a change
  to either needs an upgrade of this program.
- `proposal_activate` in the same transaction (draft flows) is currently disallowed by the
  strict shape check.
- The Squads v4 layouts are mirrored (verified against the published source) rather than
  imported, to keep the dependency surface minimal. Pin against the deployed program version.

---

# Instructions

## Requirements

- Rust + `cargo-build-sbf` from Agave 3.x or newer (platform-tools ≥ v1.52; the 2.1 toolchain's
  Rust 1.79 can't build the dependency tree). The Anchor CLI is **not** required.
- Node.js + `npm`
- [`surfpool`](https://github.com/txtx/surfpool) for local runs (forks mainnet just-in-time, so the real Squads v4 program is available)
- `jq` (bundle e2e only)
- `program-metadata` CLI (bundle e2e only, to stage the IDL buffer)

### Anchor 1.2 notes

The program uses `anchor-lang = "1.2"` and the clients use the renamed `@anchor-lang/core` (1.2)
package (formerly `@coral-xyz/anchor`). Two migration notes: in 1.x the instructions-sysvar
helpers (`load_instruction_at_checked`, `ID`) moved out of anchor's
`solana_program::sysvar::instructions` re-export into the split `solana-instructions-sysvar`
crate, which the program now depends on directly; and `@anchor-lang/core`'s client is
API-compatible with the old package for this project's usage (`Program`, `AnchorProvider`,
`Wallet`, `BN`, coders).

## Build & test

```bash
cargo test            # unit tests (host) + mainnet VaultTransaction fixture
cargo build-sbf       # deployable .so
npm install           # client dependencies for scripts/
```

## End-to-end: simple transfer proposal

`scripts/e2e.cjs` runs the full flow against a live cluster: creates a Squads v4 multisig,
funds vault 0, creates a vault transaction (0.001 SOL transfer vault → wallet) + proposal, then
submits a **tampered** approval (must fail on-chain with `DataMismatch`, no vote recorded), then
creates a decoy proposal #2 that drains the vault and tries two **substitution** attacks — honest #1
shown but the vote cast on #2 (`VoteProposalMismatch`), and #2's proposal paired with #1's
transaction (`TransactionIndexMismatch`) — and finally submits the **honest** approval (must pass,
bundled with `assert_account_hash` on the multisig account and `assert_program_revision` on this
program) and executes the vault transaction.

`run-e2e.sh` then runs `scripts/e2e-assert.cjs`: one-instruction cases for `assert_account_hash` /
`assert_program_revision`, each checked on-chain. They cover the honest paths, including Squads v4
(a large, zero-padded ProgramData), and every failure code except `NotAProgramData` (6046). That
one is defence in depth: across transactions, a loader-owned account at a Program's stored address
is always its ProgramData; it could only differ within a transaction that also closes the program. The failure cases are wrong owner, wrong or malformed hash, args/account mismatch,
ProgramData passed as the program, a non-loader account, another program's ProgramData, and a
closed program (a throwaway deploy, so the wallet needs about 3 SOL, refunded on close). The two
Squads cases run only where Squads v4 exists (surfpool, devnet, mainnet).

```bash
surfpool start                      # terminal 1: local mainnet fork (real Squads program)
./scripts/run-e2e.sh                # terminal 2: airdrops, deploys if missing, runs e2e
./scripts/run-e2e.sh devnet         # same against devnet (fund keys/e2e-wallet.json first, ~4 SOL)
./scripts/run-e2e.sh <rpc-url>      # any other cluster
```

Environment variables for `scripts/e2e.cjs`:

| Var | Meaning |
|---|---|
| `RPC_URL` | cluster endpoint |
| `WALLET` | keypair path |
| `RESUME_MULTISIG` / `RESUME_TX_INDEX` | re-enter the scenario at an existing multisig after an interruption |

Public devnet RPC rate-limits aggressively; the script paces and retries, and every step is
idempotent-or-skippable on resume.

## End-to-end: super-squads bundle (upgrade + verify + buffer hash)

`scripts/e2e-super.sh` drives the real [`super-squads`](https://github.com/tiago18c/super-squads)
CLI (cloned under `vendor/`, built as-is) to produce a genuine bundled program-authority proposal
— a loader-v3 upgrade plus an otter-verify build record — and then clear-signs the approval with
**both** instructions:

```
tx = [ verify_buffer_hash(buffer, sha256),   verify_proposal(bundle),   proposal_approve ]
```

It deploys a noop v1 program, hands its upgrade authority to a fresh multisig vault, stages a v2
buffer, runs `super-squads propose`, then submits three approvals and asserts on-chain outcomes:

1. **tampered buffer hash** → fails with `BufferHashMismatch` (6033), no vote recorded
2. **tampered expected instruction data** → fails with `DataMismatch` (6020), no vote recorded
3. **honest** → approval lands; `super-squads execute` runs the vault CPIs; the program hash is
   now v2 and the otter-verify PDA exists

```bash
scripts/e2e-super.sh                 # local surfpool (forks mainnet just-in-time)
SKIP_BUILD=1 scripts/e2e-super.sh    # skip the cargo/sbf builds after the first run
NETWORK=devnet DEPLOYER_KEYPAIR=<funded> scripts/e2e-super.sh   # live devnet
```

It needs **no** `solana-verify` binary — `scripts/program-hash.cjs` reproduces the sha256 digest
(matching `solana-verify get-program-hash`/`get-buffer-hash`, which is also what
`verify_buffer_hash` checks) directly from account data or a local `.so`.

## End-to-end: programmatic signers

`scripts/e2e-eps.cjs` votes through the ed25519 programmatic signer on a local devnet fork;
`scripts/e2e-vector.cjs` votes through Vector on a local devnet fork.

Both run against a local fork only (they refuse any non-local RPC), with the clear-signing
program deployed from `target/deploy/`. Each expected failure is checked on-chain by its error
code and by the absence of a vote; the driver's nonce must be unchanged.

**ed25519 programmatic signer** — `scripts/e2e-eps.cjs`, on a fork of devnet (which has the
signer, executor and nonce programs):

```bash
surfpool start --network devnet --no-tui --no-deploy --no-studio -y    # terminal 1
solana airdrop 100 -u http://127.0.0.1:8899 -k keys/e2e-wallet.json
solana program extend 7xs3LhQjKoCGfXm2qst7LUhismrG1bGxz5Jw6AHij7eu 80000 -u http://127.0.0.1:8899 -k keys/e2e-wallet.json
solana program deploy target/deploy/squads_clear_signing.so \
  --program-id target/deploy/squads_clear_signing-keypair.json -u http://127.0.0.1:8899 -k keys/e2e-wallet.json
node scripts/e2e-eps.cjs
```

| Case | Result |
|---|---|
| Expected data differs from the stored vault transaction | `DataMismatch` (6020) |
| Proposal #1 verified, vote cast on proposal #2 | `VoteProposalMismatch` (6026) |
| Extra instruction of another program (Memo) in the execution message | `ForbiddenInstruction` (6022) |
| `verify_proposal` used in place of `verify_proposal_cpi` | `ForbiddenInstruction` (6022) |
| `verify_proposal_cpi` as a top-level instruction | `NotInvokedViaCpi` (6048) |
| `[assert_account_hash, verify_proposal_cpi, proposal_approve]` | vote lands, about 127k CU |

The relayed transaction is 1,730 bytes, so it needs a v1 (4 KB) transaction: the authorization
message repeats every account key inline, which a lookup table cannot shrink.

**Vector** — `scripts/e2e-vector.cjs`, also on a fork of devnet, where Vector is deployed. It
defaults to port 8999, so point it at the same fork:

```bash
RPC_URL=http://127.0.0.1:8899 node scripts/e2e-vector.cjs
```

| Case | Result |
|---|---|
| Expected data differs from the stored vault transaction | `DataMismatch` (6020) |
| Proposal #1 verified, vote cast on proposal #2 | `VoteProposalMismatch` (6026) |
| One stray byte after the sub-instruction list | `EmbeddedTrailingBytes` (6053) |
| Extra System transfer sub-instruction | `ForbiddenInstruction` (6022) |
| `verify_proposal_cpi` as a top-level instruction | `NotInvokedViaCpi` (6048) |
| A second `Passthrough` voting on proposal #2, after or before the verified one | `ForbiddenDriverInstruction` (6055) |
| `[Advance, Passthrough{assert_account_hash, verify_proposal_cpi, proposal_approve}]`, member = vector account | vote lands, about 49k CU, 847 bytes (legacy transaction) |
| The same with Compute Budget instructions at top level | vote lands |
| Member = a vector account's system PDA: vote on the wrong proposal, then the honest vote | `VoteProposalMismatch` (6026), then the vote lands |
| Two signers in one `Advance` and `Passthrough`, one of them the member, in either order | vote lands, about 63k CU |

Not covered by either script: malformed driver framing, a member that signs the transaction, and
votes other than approve. The parsers' framing rules are unit-tested with hand-built fixtures.

## Approving an existing proposal

`scripts/approve-clearsign.cjs` is the reusable piece: it reads the vault transaction from chain,
builds the expected content, prepends `verify_buffer_hash` when a buffer is given, and submits the
clear-signed vote.

| Var | Meaning |
|---|---|
| `RPC_URL` | cluster (default `http://127.0.0.1:8899`) |
| `WALLET` | member keypair path (required) |
| `MULTISIG` | multisig PDA (required) |
| `TX_INDEX` | proposal / transaction index (default `1`) |
| `BUFFER` | *(optional)* loader-v3 buffer to hash-check — prepends `verify_buffer_hash` |
| `SO_FILE` | local `.so` the buffer must match (required with `BUFFER`) |
| `TAMPER` | `none` (default) \| `hash` \| `data` — corrupt one byte and **expect** the on-chain abort with no vote recorded |

```bash
WALLET=<member-keypair.json> MULTISIG=<pda> TX_INDEX=3 \
  BUFFER=<buffer> SO_FILE=<program.so> \
  node scripts/approve-clearsign.cjs
```

Exit `0` means the observed behavior matched the expectation (the honest approval landed, or the
tampered approval failed with no vote); anything else exits `1`.

## Larger bundles: version-1 (4 KB) transactions

Clear signing puts the *entire* expected bundle content inside `verify_proposal`'s args, which
makes the approval transaction grow with the bundle. A legacy/v0 transaction caps at **1232
bytes**; the upgrade+verify bundle already lands at ~1206 bytes, and adding the IDL/metadata
actions pushes it past the limit. Address lookup tables don't help — they compress the *account
list*, not `verify_proposal`'s inline instruction data.

The fix is a **version-1 transaction**, which raises the wire limit to **4096 bytes**
(`V1_TRANSACTION_SIZE_LIMIT`). v1 also folds the compute-unit limit and loaded-accounts-data-size
into the message *config* (no separate ComputeBudget instruction) and drops ALTs. `@solana/web3.js`
1.x is **read-only** for v1 (`MessageV1.serialize()` throws); building and sending a v1 transaction
requires **`@solana/kit`** 8.x.

`scripts/approve-clearsign-v1.cjs` is the kit-based approval: it reads the vault transaction and
builds the instructions with web3.js/anchor, converts them to kit instructions, and assembles a
v1 message (`createTransactionMessage({ version: 1 })` + `setTransactionMessageComputeUnitLimit`
+ `setTransactionMessageLoadedAccountsDataSizeLimit`). `verify_proposal`'s data is hand-encoded
with borsh — Anchor's client coder caps instruction data at a 1000-byte buffer, which a
multi-instruction bundle overruns (the encoding is cross-checked byte-for-byte against Anchor's
coder for small bundles). `scripts/v1-smoke.cjs` is a minimal standalone check that a cluster
accepts v1 at all.

`scripts/e2e-super.sh` stages an IDL buffer with the installed `program-metadata` CLI, proposes the
full **five-instruction** bundle (verify + metadata allocate/write/init + upgrade), and clear-signs
it with the v1 approval — the resulting transaction is ~1.8 KB, over the v0 limit and under the
v1 limit.

> **Surfpool note:** surfpool accepts v1 transactions but (as of 1.5) does **not** honor the v1
> message config's compute-unit limit — it falls back to the `200k × num_instructions` default. With
> the SHA-256 syscall the honest approval now costs well under that default, so it works on surfpool
> too; this only mattered while the buffer hash was a ~640k-CU software SHA-512. Devnet (agave 4.3)
> honors the config either way.

## Wallet integration

```ts
import * as multisig from "@sqds/multisig";

const [txPda] = multisig.getTransactionPda({ multisigPda, index });
const [proposalPda] = multisig.getProposalPda({ multisigPda, transactionIndex: index });
const txAccount = await multisig.accounts.VaultTransaction.fromAccountAddress(conn, txPda);
const msg = txAccount.message;

// Resolve the combined key table exactly like the program does:
// static keys ++ ALT writables (lookup order) ++ ALT readonlys.
const altAccounts = await Promise.all(
  msg.addressTableLookups.map(l => conn.getAddressLookupTable(l.accountKey)));
const loadedWritable = msg.addressTableLookups.flatMap((l, i) =>
  l.writableIndexes.map(x => altAccounts[i].value.state.addresses[x]));
const loadedReadonly = msg.addressTableLookups.flatMap((l, i) =>
  l.readonlyIndexes.map(x => altAccounts[i].value.state.addresses[x]));
const keys = [...msg.accountKeys, ...loadedWritable, ...loadedReadonly];

const isSigner = (i: number) => i < msg.numSigners;
const isWritable = (i: number) =>
  i < msg.accountKeys.length
    ? (i < msg.numWritableSigners ||
       (i >= msg.numSigners && i - msg.numSigners < msg.numWritableNonSigners))
    : i - msg.accountKeys.length < loadedWritable.length;

const expectedInstructions = msg.instructions.map(ix => ({
  programId: keys[ix.programIdIndex],
  accounts: ix.accountIndexes.map(i => ({
    pubkey: keys[i], isSigner: isSigner(i), isWritable: isWritable(i) })),
  data: Buffer.from(ix.data),
}));

const verifyIx = await clearSigningProgram.methods
  .verifyProposal({
    multisig: multisigPda,
    transactionIndex: index,
    vaultIndex: txAccount.vaultIndex,
    numEphemeralSigners: txAccount.ephemeralSignerBumps.length,
    member: memberPubkey,
    action: { approve: {} },
    instructions: expectedInstructions,
  })
  .accounts({ proposal: proposalPda, transaction: txPda, instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY })
  .remainingAccounts(msg.addressTableLookups.map(l =>
    ({ pubkey: l.accountKey, isSigner: false, isWritable: false })))
  .instruction();

const approveIx = multisig.instructions.proposalApprove({ multisigPda, transactionIndex: index, member: memberPubkey });
// tx = [verifyIx, approveIx]  → send to the offline device for signing.
```

For upgrade proposals, prepend `verify_buffer_hash({ buffer, expectedHash })` where
`expectedHash` is the 64-char lowercase hex from `solana-verify get-buffer-hash` (or
`scripts/program-hash.cjs`).

To pin other state, prepend any number of:

```js
await program.methods
  .assertAccountHash({ account, owner /* PublicKey | null */, expectedHash: sha256Hex(info.data) })
  .accounts({ account })
  .instruction();

// programData = the address stored at bytes 4..36 of the program account
await program.methods
  .assertProgramRevision({ program: programId, expectedHash /* solana-verify get-program-hash */ })
  .accounts({ program: programId, programData })
  .instruction();
```

For a programmatic signer, build `verify_proposal_cpi` with the same args, and place it and the
vote in the driver's embedded list instead of the transaction:

```js
await program.methods
  .verifyProposalCpi(args)
  .accounts({ proposal: proposalPda, transaction: txPda,
              instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY, member: memberPda })
  .remainingAccounts(/* lookup tables, as above */)
  .instruction();
```

`args.member` is the PDA. The embedded list may hold only this program's instructions and the
vote: no Compute Budget instruction.

## Repo layout

- `programs/squads-clear-signing/src/lib.rs` — entrypoint, accounts, IDL-visible arg types (`verify_proposal`, `verify_proposal_cpi`, `verify_buffer_hash`, `assert_account_hash`, `assert_program_revision`)
- `programs/squads-clear-signing/src/squads.rs` — mirrored Squads v4 layouts (VaultTransaction, Proposal header), discriminators
- `programs/squads-clear-signing/src/validation.rs` — pure validation logic (message diff, ALT resolution, buffer/program/account hashing, top-level and embedded shape checks) + unit tests
- `programs/squads-clear-signing/src/errors.rs` — granular failure codes
- `programs/squads-clear-signing/tests/mainnet_fixture.rs` — decodes a real mainnet VaultTransaction
- `scripts/e2e.cjs` / `run-e2e.sh` — simple system-transfer proposal, tampered vs honest approval
- `scripts/e2e-assert.cjs` — on-chain cases for `assert_account_hash` / `assert_program_revision`
- `scripts/e2e-eps.cjs` — vote through the ed25519 programmatic signer on a local devnet fork
- `scripts/e2e-vector.cjs` — vote through Vector on a local devnet fork
- `scripts/e2e-super.sh` — full super-squads bundle (upgrade + verify + idl) with buffer-hash + v1
- `scripts/approve-clearsign.cjs` — reusable clear-signed approval builder, legacy tx (+ tamper modes)
- `scripts/approve-clearsign-v1.cjs` — kit-based clear-signed approval as a v1 (4 KB) transaction
- `scripts/v1-smoke.cjs` — minimal check that a cluster accepts a v1 transaction
- `scripts/program-hash.cjs` — sha256/sha512 program & buffer hashing without solana-verify
- `docs/img/` — diagrams used in this README
- `vendor/super-squads/` — upstream CLI clone (git-ignored), built as-is for the bundle e2e
