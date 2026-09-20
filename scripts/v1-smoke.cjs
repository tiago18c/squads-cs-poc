#!/usr/bin/env node
// Smoke test: build, sign, and send a *version 1* transaction via @solana/kit,
// confirming the target cluster accepts v1 (4KB limit). Sends a tiny memo.
const fs = require("fs");
const kit = require("@solana/kit");

const URL = process.env.RPC_URL || "http://127.0.0.1:8899";
const WALLET = process.env.WALLET || "keys/e2e-wallet.json";
const MEMO = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const rpc = kit.createSolanaRpc(URL);
  const secret = Uint8Array.from(JSON.parse(fs.readFileSync(WALLET)));
  const signer = await kit.createKeyPairSignerFromBytes(secret);
  console.log("signer:", signer.address);

  const { value: latest } = await rpc.getLatestBlockhash({ commitment: "confirmed" }).send();
  const memoIx = {
    programAddress: kit.address(MEMO),
    accounts: [],
    data: new TextEncoder().encode("clear-signing v1 smoke"),
  };

  const message = kit.pipe(
    kit.createTransactionMessage({ version: 1 }),
    (m) => kit.setTransactionMessageFeePayerSigner(signer, m),
    (m) => kit.setTransactionMessageLifetimeUsingBlockhash(latest, m),
    // v1 folds resource limits into the message config; unset => 0, so set them.
    (m) => kit.setTransactionMessageComputeUnitLimit(200_000, m),
    (m) => kit.setTransactionMessageLoadedAccountsDataSizeLimit(2_000_000, m),
    (m) => kit.appendTransactionMessageInstruction(memoIx, m),
  );
  console.log("message version:", message.version);

  const signed = await kit.signTransactionMessageWithSigners(message);
  const wire = kit.getBase64EncodedWireTransaction(signed);
  console.log("wire base64 bytes:", Buffer.from(wire, "base64").length, "(v1 limit 4096)");

  const sig = await rpc.sendTransaction(wire, { encoding: "base64", skipPreflight: false }).send();
  console.log("sent v1 tx:", sig);

  for (let i = 0; i < 30; i++) {
    const { value } = await rpc.getSignatureStatuses([sig]).send();
    const st = value[0];
    if (st && (st.confirmationStatus === "confirmed" || st.confirmationStatus === "finalized")) {
      if (st.err) throw new Error("v1 tx failed: " + JSON.stringify(st.err));
      console.log(`\x1b[32m✔ v1 transaction confirmed on-chain\x1b[0m (${st.confirmationStatus})`);
      return;
    }
    await sleep(2000);
  }
  throw new Error("v1 tx not confirmed in time");
})().catch((e) => { console.error("\x1b[31m✗\x1b[0m", e.message || e); process.exit(1); });
