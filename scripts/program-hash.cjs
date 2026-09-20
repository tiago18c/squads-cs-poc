#!/usr/bin/env node
/**
 * Program/buffer hashing without solana-verify installed, both digests:
 *   sha256 — byte-identical to `solana-verify get-program-hash / get-executable-hash`
 *   sha512 — the same trimming convention hashed with SHA-512 (legacy option;
 *            verify_buffer_hash now uses the sha256 digest above)
 *
 * Usage:
 *   node program-hash.cjs <program-pubkey>            # deployed loader-v3 program (needs RPC_URL)
 *   node program-hash.cjs --buffer <buffer-pubkey>    # loader-v3 buffer account (needs RPC_URL)
 *   node program-hash.cjs --file <path.so>            # local artifact
 * Options: --sha512 to print the sha512 digest instead of sha256.
 */
const fs = require("fs");
const crypto = require("crypto");
const { Connection, PublicKey } = require("@solana/web3.js");

const PROGRAMDATA_METADATA_SIZE = 45; // 4 tag + 8 slot + 33 authority option
const BUFFER_METADATA_SIZE = 37; // 4 tag + 33 authority option

function trim(bytes) {
  let end = bytes.length;
  while (end > 0 && bytes[end - 1] === 0) end--;
  return bytes.subarray(0, end);
}
const digest = (algo, bytes) => crypto.createHash(algo).update(trim(bytes)).digest("hex");

async function main() {
  const args = process.argv.slice(2);
  const algo = args.includes("--sha512") ? "sha512" : "sha256";
  const positional = args.filter((a) => !a.startsWith("--"));
  const target = positional[0];
  if (!target) throw new Error("usage: program-hash.cjs [--sha512] (<program>|--buffer <buffer>|--file <so>)");

  if (args.includes("--file")) {
    console.log(digest(algo, fs.readFileSync(target)));
    return;
  }

  const connection = new Connection(process.env.RPC_URL || "http://127.0.0.1:8899", "confirmed");
  const key = new PublicKey(target);
  const info = await connection.getAccountInfo(key);
  if (!info) throw new Error(`account ${target} not found`);

  if (args.includes("--buffer")) {
    if (info.data.readUInt32LE(0) !== 1) throw new Error("not a Buffer account");
    console.log(digest(algo, info.data.subarray(BUFFER_METADATA_SIZE)));
    return;
  }

  // Program account (tag 2) -> programdata address -> ELF at offset 45.
  if (info.data.readUInt32LE(0) !== 2) throw new Error("not a loader-v3 Program account");
  const programData = new PublicKey(info.data.subarray(4, 36));
  const pd = await connection.getAccountInfo(programData);
  if (!pd) throw new Error(`programdata ${programData} not found`);
  console.log(digest(algo, pd.data.subarray(PROGRAMDATA_METADATA_SIZE)));
}

main().catch((e) => { console.error(String(e.message || e)); process.exit(1); });
