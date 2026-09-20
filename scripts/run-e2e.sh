#!/usr/bin/env bash
# Run the clear-signing e2e scenario.
#   ./scripts/run-e2e.sh            # against surfpool on 127.0.0.1:8899 (start it first)
#   ./scripts/run-e2e.sh devnet     # against devnet (wallet must be funded)
#   ./scripts/run-e2e.sh <rpc-url>  # against any RPC
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET="${1:-surfpool}"
case "$TARGET" in
  surfpool|local) URL="http://127.0.0.1:8899" ;;
  devnet)         URL="https://api.devnet.solana.com" ;;
  *)              URL="$TARGET" ;;
esac

WALLET=keys/e2e-wallet.json
PROGRAM_KP=target/deploy/squads_clear_signing-keypair.json
PROGRAM_ID=$(solana-keygen pubkey "$PROGRAM_KP")

# Airdrop on local clusters if the wallet is dry (deploy needs ~2 SOL).
if [[ "$URL" == *127.0.0.1* ]]; then
  BAL=$(solana balance -u "$URL" -k "$WALLET" | awk '{print $1}')
  if awk "BEGIN{exit !($BAL < 3)}"; then
    solana airdrop 20 -u "$URL" -k "$WALLET" >/dev/null
  fi
fi

# Deploy the program if this cluster doesn't have it yet.
if ! solana account "$PROGRAM_ID" -u "$URL" >/dev/null 2>&1; then
  echo "deploying squads_clear_signing ($PROGRAM_ID) ..."
  solana program deploy target/deploy/squads_clear_signing.so \
    --program-id "$PROGRAM_KP" -u "$URL" -k "$WALLET"
else
  echo "program already deployed: $PROGRAM_ID"
fi

RPC_URL="$URL" node scripts/e2e.cjs
