import { BarretenbergVerifier } from "@noir-lang/backend_barretenberg";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const PINNED_NOIR_VERSION = "0.32.0";
const PINNED_BBJS_VERSION = "0.46.1";
const runtimeDir = path.dirname(fileURLToPath(import.meta.url));

import os from "node:os";
os.cpus = () => [{ }]; // Force os.cpus().length to be 1 to prevent WASM thread thrashing

function fail(message) {
  process.stderr.write(message + "\n");
  process.exit(1);
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function asBytes(hex, label) {
  if (typeof hex !== "string" || !/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    fail(`${label} must be even-length hex`);
  }
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

const raw = await readStdin();
let payload;
try {
  payload = JSON.parse(raw);
} catch {
  fail("stdin is not valid JSON");
}

if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
  fail("payload must be an object");
}
if (payload.noirVersion !== PINNED_NOIR_VERSION || payload.barretenbergVersion !== PINNED_BBJS_VERSION) {
  fail("payload toolchain version mismatch");
}
if (!Array.isArray(payload.publicInputs) || payload.publicInputs.some((item) => typeof item !== "string")) {
  fail("publicInputs must be an array of hex strings");
}

async function assertInstalledVersion(packageName, expectedVersion) {
  const packagePath = path.join(runtimeDir, "node_modules", ...packageName.split("/"), "package.json");
  const packageMetadata = JSON.parse(await readFile(packagePath, "utf8"));
  if (packageMetadata.version !== expectedVersion) {
    fail(`${packageName} version mismatch`);
  }
}

try {
  await assertInstalledVersion("@noir-lang/backend_barretenberg", PINNED_NOIR_VERSION);
  await assertInstalledVersion("@aztec/bb.js", PINNED_BBJS_VERSION);
} catch {
  fail("Pinned verifier dependencies are unavailable or invalid");
}

const proof = asBytes(payload.proofHex, "proofHex");
const verificationKey = asBytes(payload.verificationKeyHex, "verificationKeyHex");
const proofData = {
  proof,
  publicInputs: payload.publicInputs,
};

const verifier = new BarretenbergVerifier();
try {
  const verified = await verifier.verifyProof(proofData, verificationKey);
  process.stdout.write(JSON.stringify({ verified: verified === true }));
} catch {
  process.stderr.write("Barretenberg initialization or proof verification failed\n");
  process.exitCode = 1;
} finally {
  await verifier.destroy();
}

process.exit(process.exitCode || 0);
