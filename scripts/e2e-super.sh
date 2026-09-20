#!/usr/bin/env bash
#
# Clear-signing e2e over a super-squads bundle (upgrade + otter-verify), adapted from
# vendor/super-squads/e2e/run.sh:
#
#   1. deploy a loader-v3 "noop" program (v1), owned by the deployer
#   2. create a Squads multisig; hand the program's upgrade authority to the vault
#   3. stage a BPF buffer with noop v2 (authority -> vault)
#   4. deploy squads_clear_signing
#   5. `super-squads propose` -> one bundled proposal (upgrade + verify)
#   6. TAMPERED approvals, both expected to fail on-chain with no vote:
#        a. [verify_buffer_hash(wrong sha512), verify_proposal, approve]
#        b. [verify_buffer_hash(ok), verify_proposal(wrong data), approve]
#   7. HONEST approval [verify_buffer_hash, verify_proposal, approve] -> vote lands
#   8. `super-squads execute`; assert program hash == v2 and the verify PDA exists
#
# Usage:  scripts/e2e-super.sh                  # local surfpool (forks mainnet)
#         NETWORK=devnet scripts/e2e-super.sh   # live devnet (fund DEPLOYER_KEYPAIR first)
# Env:    NETWORK, DATASOURCE_RPC, RPC_PORT, RPC_URL, DEPLOYER_KEYPAIR, MIN_BALANCE,
#         SKIP_BUILD=1, KEEP=1 — same semantics as the vendored suite.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
VENDOR="$ROOT/vendor/super-squads"
source "$VENDOR/e2e/lib.sh"

# ---- config (mirrors the vendored run.sh) -----------------------------------
NETWORK="${NETWORK:-local}"
case "$NETWORK" in
  local)
    DATASOURCE_RPC="${DATASOURCE_RPC:-https://api.mainnet-beta.solana.com}"
    RPC_PORT="${RPC_PORT:-8899}"
    RPC_URL="http://127.0.0.1:${RPC_PORT}"
    # Assigned unconditionally (lib.sh, sourced above, has already set these to its
    # own defaults, so a `:-` fallback here would be a no-op).
    POLL_TIMEOUT=60; POLL_INTERVAL=1
    ;;
  devnet)
    RPC_URL="${RPC_URL:-https://api.devnet.solana.com}"
    POLL_TIMEOUT=150; POLL_INTERVAL=3
    ;;
  *) die "unknown NETWORK '$NETWORK' (use 'local' or 'devnet')" ;;
esac
export RPC_URL
WORK="$ROOT/.work-super"
SURF_LOG="$WORK/surfpool.log"
MAX_LEN="${MAX_LEN:-40000}"
VAULT_FUND="${VAULT_FUND:-0.3}"

SS="$VENDOR/target/release/super-squads"
SQUADS_CREATE="$VENDOR/target/release/squads-create"
V1_SO="$VENDOR/e2e/programs/noop-v1/target/deploy/noop_v1.so"
V2_SO="$VENDOR/e2e/programs/noop-v2/target/deploy/noop_v2.so"
CS_SO="$ROOT/target/deploy/squads_clear_signing.so"
CS_KP="$ROOT/target/deploy/squads_clear_signing-keypair.json"

DEPLOYER_KP="$WORK/deployer.json"
PROGRAM_KP="$WORK/program.json"
BPF_BUFFER_KP="$WORK/bpf-buffer.json"

VERIFY_REPO="https://github.com/example/noop"
VERIFY_COMMIT="0000000000000000000000000000000000000001"
LIBRARY_NAME="noop"

# No solana-verify needed: same digests via scripts/program-hash.cjs.
program_hash() { node "$HERE/program-hash.cjs" "$1" 2>/dev/null; }
file_hash()    { node "$HERE/program-hash.cjs" --file "$1"; }

# Locally-installed kit-based program-metadata CLI (staging IDL buffers).
PMETA="$ROOT/node_modules/.bin/program-metadata"
IDL_FIXTURE="$VENDOR/e2e/fixtures/idl-v1.json"
idl_contains() { "$PMETA" fetch idl "$1" --rpc "$RPC_URL" 2>/dev/null | grep -qF "$2"; }
# Stage a program-metadata buffer holding <file>, hand its authority to the vault,
# and echo the buffer address.
stage_idl_buffer() { # <file>
  local out buffer
  out="$("$PMETA" create-buffer "$1" --keypair "$DEPLOYER_KP" --rpc "$RPC_URL" \
        --compression none --encoding utf8 --format json 2>&1)"
  echo "$out" >>"$WORK/create-buffer.log"
  # buffer address is the first 32-44 char base58 token (tx sigs are ~88 chars).
  buffer="$(grep -oE '[1-9A-HJ-NP-Za-km-z]{32,44}' <<<"$out" | head -n1)"
  [[ -n "$buffer" ]] || return 1
  "$PMETA" set-buffer-authority "$buffer" --keypair "$DEPLOYER_KP" --rpc "$RPC_URL" \
    --new-authority "$VAULT" >>"$WORK/create-buffer.log" 2>&1
  echo "$buffer"
}
# Override lib.sh's predicate: read at `confirmed`, and pass --keypair because
# `solana program show` refuses to run without a configured default signer even
# for a read (there is no ~/.config/solana/id.json in this environment).
upgrade_auth_is() { [[ "$(solana program show "$1" --url "$RPC_URL" --commitment confirmed --keypair "$DEPLOYER_KP" 2>/dev/null | awk -F': *' '/^Authority:/{print $2}')" == "$2" ]]; }

# ---- teardown ---------------------------------------------------------------
cleanup() {
  local rc=$?
  if [[ -n "${SURF_PID:-}" ]] && kill -0 "$SURF_PID" 2>/dev/null; then
    if [[ "${KEEP:-}" == "1" ]]; then
      warn "KEEP=1: leaving surfpool running (pid $SURF_PID) on $RPC_URL"
    else
      stop_surfpool
    fi
  fi
  if [[ $rc -ne 0 && "$NETWORK" == "local" ]]; then
    printf '\n%s---- surfpool log (tail) ----%s\n' "$C_DIM" "$C_RESET" >&2
    tail -n 40 "$SURF_LOG" 2>/dev/null >&2 || true
  fi
  exit $rc
}
trap cleanup EXIT

sol() { solana "$@" --url "$RPC_URL" --commitment confirmed; }
at_least() { awk "BEGIN{exit !($1 >= $2)}"; }

ensure_funds_devnet() {
  local target="${MIN_BALANCE:-4}" bal
  bal="$(sol balance "$DEPLOYER" 2>/dev/null | awk '{print $1}')"; bal="${bal:-0}"
  at_least "$bal" "$target" && { ok "deployer pre-funded: $bal SOL"; return; }
  local i
  for i in 1 2 3 4 5; do
    solana airdrop 2 "$DEPLOYER" --url "$RPC_URL" >/dev/null 2>&1 || true
    bal="$(sol balance "$DEPLOYER" 2>/dev/null | awk '{print $1}')"; bal="${bal:-0}"
    at_least "$bal" "$target" && break; sleep 3
  done
  at_least "$bal" "$target" || die "could not fund deployer to $target SOL (have $bal). Pass DEPLOYER_KEYPAIR=<funded keypair>."
  ok "deployer funded: $bal SOL"
}

# ============================================================================
step "Build binaries and test programs"
if [[ "${SKIP_BUILD:-}" == "1" ]]; then
  info "SKIP_BUILD=1 — reusing existing artifacts"
else
  ( cd "$VENDOR" && cargo build --release -p super-squads -p squads-create ) >/dev/null 2>&1 \
    || die "super-squads cargo build failed"
  for p in noop-v1 noop-v2; do
    ( cd "$VENDOR/e2e/programs/$p" && cargo-build-sbf ) >/dev/null 2>&1 || die "cargo-build-sbf failed for $p"
  done
  ( cd "$ROOT" && cargo build-sbf ) >/dev/null 2>&1 || die "cargo build-sbf failed for squads_clear_signing"
fi
for f in "$SS" "$SQUADS_CREATE" "$V1_SO" "$V2_SO" "$CS_SO" "$CS_KP"; do
  [[ -e "$f" ]] || die "missing $f"
done
V1_HASH="$(file_hash "$V1_SO")"
V2_HASH="$(file_hash "$V2_SO")"
ok "noop v1 sha256: $V1_HASH"
ok "noop v2 sha256: $V2_HASH"
[[ "$V1_HASH" != "$V2_HASH" ]] || die "v1 and v2 hashes identical"
CS_PROGRAM="$(solana-keygen pubkey "$CS_KP")"
ok "clear-signing program id: $CS_PROGRAM"

# ============================================================================
step "Prepare workspace and keypairs"
rm -rf "$WORK"; mkdir -p "$WORK"
solana-keygen new --no-bip39-passphrase --silent -o "$PROGRAM_KP" -f
solana-keygen new --no-bip39-passphrase --silent -o "$BPF_BUFFER_KP" -f
if [[ -n "${DEPLOYER_KEYPAIR:-}" ]]; then
  cp "$DEPLOYER_KEYPAIR" "$DEPLOYER_KP"
  info "using provided deployer keypair $DEPLOYER_KEYPAIR"
else
  solana-keygen new --no-bip39-passphrase --silent -o "$DEPLOYER_KP" -f
fi
DEPLOYER="$(solana address -k "$DEPLOYER_KP")"
PROGRAM="$(solana address -k "$PROGRAM_KP")"
BPF_BUFFER="$(solana address -k "$BPF_BUFFER_KP")"
ok "deployer: $DEPLOYER"
ok "program:  $PROGRAM"

# ============================================================================
if [[ "$NETWORK" == "local" ]]; then
  step "Boot surfpool (forking mainnet, airdropping the deployer)"
  start_surfpool "$SURF_LOG"
  wait_for_rpc
  ok "deployer funded: $(sol balance "$DEPLOYER" | awk '{print $1}') SOL"
else
  step "Target live $NETWORK"
  info "rpc: $RPC_URL"
  ensure_funds_devnet
fi

# ============================================================================
step "Deploy noop v1 (deployer holds the upgrade authority)"
sol program deploy "$V1_SO" \
  --program-id "$PROGRAM_KP" --keypair "$DEPLOYER_KP" \
  --upgrade-authority "$DEPLOYER_KP" --use-rpc --max-len "$MAX_LEN" >/dev/null
DEPLOYED_HASH="$(retry_stdout "program $PROGRAM to become queryable" program_hash "$PROGRAM")" \
  || die "deployed program never became queryable"
assert_eq "deployed program hash == v1" "$V1_HASH" "$DEPLOYED_HASH"

# ============================================================================
step "Deploy squads_clear_signing"
if [[ -z "$(account_owner "$CS_PROGRAM")" ]]; then
  sol program deploy "$CS_SO" --program-id "$CS_KP" --keypair "$DEPLOYER_KP" --use-rpc >/dev/null
  poll "clear-signing program to be visible" owner_is "$CS_PROGRAM" "BPFLoaderUpgradeab1e11111111111111111111111"
  ok "deployed $CS_PROGRAM"
else
  ok "already deployed: $CS_PROGRAM"
fi

# ============================================================================
step "Create the Squads multisig"
MS_JSON="$("$SQUADS_CREATE" --url "$RPC_URL" --keypair "$DEPLOYER_KP")"
echo "$MS_JSON" | jq . >"$WORK/multisig.json"
MULTISIG="$(jq -r .multisig "$WORK/multisig.json")"
VAULT="$(jq -r .vault "$WORK/multisig.json")"
[[ -n "$MULTISIG" && "$MULTISIG" != null ]] || die "multisig creation failed: $MS_JSON"
ok "multisig: $MULTISIG"
ok "vault:    $VAULT"

# ============================================================================
step "Fund the vault; hand program + buffer authority to it"
sol transfer "$VAULT" "$VAULT_FUND" --keypair "$DEPLOYER_KP" --allow-unfunded-recipient >/dev/null
poll "vault to reflect funding" has_lamports "$VAULT"
sol program set-upgrade-authority "$PROGRAM" --keypair "$DEPLOYER_KP" \
  --new-upgrade-authority "$VAULT" --skip-new-upgrade-authority-signer-check >/dev/null
poll "upgrade authority -> vault" upgrade_auth_is "$PROGRAM" "$VAULT"
sol program write-buffer "$V2_SO" --keypair "$DEPLOYER_KP" \
  --buffer "$BPF_BUFFER_KP" --buffer-authority "$DEPLOYER_KP" --use-rpc >/dev/null
sol program set-buffer-authority "$BPF_BUFFER" --keypair "$DEPLOYER_KP" \
  --new-buffer-authority "$VAULT" >/dev/null
poll "bpf buffer to be visible" owner_is "$BPF_BUFFER" "BPFLoaderUpgradeab1e11111111111111111111111"
ok "buffer: $BPF_BUFFER (authority -> vault)"
assert_eq "on-chain buffer hash == v2 .so" "$V2_HASH" "$(retry_stdout "buffer hash" node "$HERE/program-hash.cjs" --buffer "$BPF_BUFFER")"

# ============================================================================
step "Stage the IDL metadata buffer (authority -> vault)"
IDL_BUFFER="$(stage_idl_buffer "$IDL_FIXTURE")" || die "could not stage IDL buffer; see $WORK/create-buffer.log"
assert_owner_eventually "IDL buffer owned by program-metadata" \
  "$IDL_BUFFER" "ProgM6JCCvbYkfKqJYHePx4xxSUSqJp7rh8Lyv7nk7S"
ok "idl buffer: $IDL_BUFFER (authority -> vault)"

# ============================================================================
step "super-squads propose (bundle: upgrade + verify + idl-create)"
"$SS" propose \
  --url "$RPC_URL" --keypair "$DEPLOYER_KP" \
  --multisig "$MULTISIG" --program "$PROGRAM" \
  --upgrade-from-buffer "$BPF_BUFFER" \
  --verify-repo "$VERIFY_REPO" --commit "$VERIFY_COMMIT" --library-name "$LIBRARY_NAME" \
  --idl-from-buffer "$IDL_BUFFER" \
  --out-dir "$WORK"
ARTIFACT="$WORK/1.artifact.json"
[[ -f "$ARTIFACT" ]] || die "expected artifact $ARTIFACT"
assert_eq "preflight blockers" "0" "$(jq -r '.blockers | length' "$ARTIFACT")"
TX_PDA="$(jq -r '.transaction_pda' "$ARTIFACT")"
poll "proposal to be visible" proposal_visible "$TX_PDA"
INSPECT="$("$SS" inspect --url "$RPC_URL" --transaction "$TX_PDA" --json)"
echo "$INSPECT" | jq . >"$WORK/inspect.json"
N_ACTIONS="$(jq '.actions | length' <<<"$INSPECT")"
ok "bundle has $N_ACTIONS instructions: $(jq -r '.actions[].kind' <<<"$INSPECT" | tr '\n' ' ')"
KINDS="$(jq -r '.actions[].kind' <<<"$INSPECT" | tr '\n' ' ')"
assert_contains "inspect kinds" "$KINDS" "verification"
assert_contains "inspect kinds" "$KINDS" "program-upgrade"
assert_contains "inspect kinds" "$KINDS" "metadata"
assert_eq "inspect buffer hash == v2" "$V2_HASH" \
  "$(jq -r '.actions[] | select(.kind=="program-upgrade") | .fields.buffer_program_hash' <<<"$INSPECT")"
VERIFY_PDA="$(jq -r '.actions[] | select(.name=="verification") | .notes[] | select(.[0]=="verify_pda") | .[1]' "$ARTIFACT")"

# ============================================================================
CLEARSIGN_ENV=(RPC_URL="$RPC_URL" WALLET="$DEPLOYER_KP" MULTISIG="$MULTISIG" TX_INDEX=1 \
               BUFFER="$BPF_BUFFER" SO_FILE="$V2_SO")

step "Clear-sign approve (v1 tx), TAMPERED buffer hash — must fail on-chain"
env "${CLEARSIGN_ENV[@]}" TAMPER=hash node "$HERE/approve-clearsign-v1.cjs" \
  || die "tampered-hash scenario did not behave as expected"
ASSERT_N=$((ASSERT_N + 1))

step "Clear-sign approve (v1 tx), TAMPERED expected instruction data — must fail on-chain"
env "${CLEARSIGN_ENV[@]}" TAMPER=data node "$HERE/approve-clearsign-v1.cjs" \
  || die "tampered-data scenario did not behave as expected"
ASSERT_N=$((ASSERT_N + 1))

step "Clear-sign approve (v1 tx), HONEST — 4KB bundle: buffer hash + full content verified"
env "${CLEARSIGN_ENV[@]}" node "$HERE/approve-clearsign-v1.cjs" \
  || die "honest clear-signed approval failed"
assert_status_eventually "proposal status after approve" "$TX_PDA" "Approved"

# ============================================================================
step "super-squads execute (vault CPIs: upgrade + verify + idl-create)"
"$SS" execute --url "$RPC_URL" --keypair "$DEPLOYER_KP" --multisig "$MULTISIG" --index 1 >/dev/null
assert_status_eventually "proposal status after execute" "$TX_PDA" "Executed"

# ============================================================================
step "Assert on-chain state (program v2, verification recorded, canonical IDL created)"
assert_program_hash_eventually "on-chain program hash == v2" "$PROGRAM" "$V2_HASH"
assert_ne "on-chain program hash != v1" "$V1_HASH" "$(program_hash "$PROGRAM")"
assert_owner_eventually "verify PDA owned by otter-verify" \
  "$VERIFY_PDA" "verifycLy8mB96wd9wqq3WDXQwM4oU6r42Th37Db9fC"
assert_idl_contains_eventually "canonical IDL created by the bundle" "$PROGRAM" "0.1.0"

# ============================================================================
printf '\n%s== PASSED — %d assertions, all green ==%s\n' "$C_BOLD$C_GREEN" "$ASSERT_N" "$C_RESET"
if [[ "$NETWORK" != "local" ]]; then
  info "left on $NETWORK: program $PROGRAM, multisig $MULTISIG, clear-signing $CS_PROGRAM"
fi
