// Pins the vendored signer (tclk-signing.mjs) to the venue's signing contract.
// The known-answer vector was cross-checked on 2026-11-12 three ways: byte-identical to
// @flop-labs/tclk-mcp 0.1.0's signing.js over 200 random seeds, and both the DID and the
// signature reproduced and verified by technocore_agent.py (the `cryptography` library).
import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalMessage, didFromPublicKey, nextNonce, signerFromSeed, sweep } from "./tclk-signing.mjs";

const SEED = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const KAT = {
  did: "did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7",
  text: "tclk1 known answer vector",
  nonce: 1731400000000,
  sig: "_pVbbzW0rnpqFqUMDHEVVTwV7QHcABYNI50TePAonTmZelii8hKow8OHsNhoJrzQbIxe1H6A4vjTjgg3Mh-4Dg",
};

test("known-answer DID and signature", () => {
  const signer = signerFromSeed(SEED);
  assert.equal(signer.did, KAT.did);
  assert.equal(signer.sign(canonicalMessage("tclk-offers", KAT.nonce, KAT.text)), KAT.sig);
});

test("sweep turns invisibles into spaces and trims, before signing", () => {
  assert.equal(sweep("  tclk1 known​answer\nvector "), KAT.text);
  assert.equal(sweep("a b c\u0000d"), "a b c d");
  assert.equal(sweep("Việt 🚀"), "Việt 🚀");
});

test("canonical message is room|nonce|text", () => {
  assert.equal(canonicalMessage("r", 7, "x|y"), "r|7|x|y");
});

test("signatures are 86-char canonical base64url", () => {
  const signer = signerFromSeed(SEED);
  for (let i = 0; i < 50; i++) {
    assert.match(signer.sign(`tclk-offers|${i}|m${i}`), /^[A-Za-z0-9_-]{85}[AQgw]$/);
  }
});

test("wrong-length keys are refused", () => {
  assert.throws(() => signerFromSeed(new Uint8Array(31)), /seed must be 32 bytes/);
  assert.throws(() => didFromPublicKey(new Uint8Array(33)), /public key must be 32 bytes/);
});

test("nonces strictly increase within a process", () => {
  let last = nextNonce();
  for (let i = 0; i < 1000; i++) {
    const next = nextNonce();
    assert.ok(next > last);
    last = next;
  }
});
