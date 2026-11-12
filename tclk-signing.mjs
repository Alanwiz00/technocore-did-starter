// SPDX-License-Identifier: Apache-2.0
//
// Vendored from @flop-labs/tclk-mcp 0.1.0, dist/signing.js
// (https://github.com/flop-labs/tclk). Copyright 2026 FLOP Labs. Its NOTICE reads:
//
//   tclk
//   Copyright 2026 FLOP Labs
//   This product includes software developed at FLOP Labs (https://flop.network).
//   Licensed under the Apache License, Version 2.0.
//
// Modified (2026-11-12): only the five helpers deal.mjs uses were kept (loadSigner and
// parseSeed dropped) and error prefixes renamed. deal.mjs used to deep-import this file
// from tclk-mcp. That package's MCP server half pulls in @modelcontextprotocol/sdk and
// zod (GHSA-mrhx-c7xc-m3w5, no fix within its zod ^3 range), none of which signing
// touches. Vendoring drops that whole tree and the reliance on an unexported path.
// tclk-signing.test.mjs pins this copy to the venue's contract; behaviour is unchanged.
//
// The technocore signed lane's client half: the single-line sweep, the canonical
// string, Ed25519 over it, and the `did:key:z6Mk…` the venue verifies against.
//   * the signature covers the text AFTER the sweep — the bytes that get stored, so a
//     stored record re-verifies from its exported line alone;
//   * the canonical string is `<room>|<nonce>|<text>`;
//   * the signature travels as 86 UNPADDED base64url characters, canonical — the last
//     character is always one of A/Q/g/w;
//   * the nonce must exceed the last one this key used in that room.
// The seed never leaves this module: a signer exposes the DID and a signing function.
import { ed25519 } from "@noble/curves/ed25519.js";
import { base58, base64urlnopad } from "@scure/base";

export const DID_PREFIX = "did:key:";
/** multicodec `ed25519-pub`, the two bytes that precede the raw public key. */
const MULTICODEC_ED25519 = Uint8Array.from([0xed, 0x01]);
/** What technocore's `clean_text` replaces with a space: Cc, Cf, Cs, Co, Zl, Zp. */
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zl}\p{Zp}]/gu;
/** Canonical unpadded base64url of 64 bytes: 86 chars, last one carrying 2 bits. */
const CANONICAL_SIG = /^[A-Za-z0-9_-]{85}[AQgw]$/;

/** The single-line sweep, minus the service's own empty/too-long refusals. */
export function sweep(text) {
  return text.replace(INVISIBLE, " ").trim();
}

/** The string an Ed25519 room-message signature covers, UTF-8. */
export function canonicalMessage(room, nonce, sweptText) {
  return `${room}|${nonce}|${sweptText}`;
}

let lastNonce = 0;
/** Milliseconds since the epoch, bumped past the last value this process issued. */
export function nextNonce() {
  lastNonce = Math.max(Date.now(), lastNonce + 1);
  return lastNonce;
}

/** The `did:key:z6Mk…` for a raw 32-byte Ed25519 public key. */
export function didFromPublicKey(publicKey) {
  if (publicKey.length !== 32) {
    throw new Error(`tclk-signing: ed25519 public key must be 32 bytes, got ${publicKey.length}`);
  }
  const multi = new Uint8Array(MULTICODEC_ED25519.length + publicKey.length);
  multi.set(MULTICODEC_ED25519, 0);
  multi.set(publicKey, MULTICODEC_ED25519.length);
  return `${DID_PREFIX}z${base58.encode(multi)}`;
}

/** A signer from a raw 32-byte Ed25519 seed. The seed stays in the closure. */
export function signerFromSeed(seed) {
  if (seed.length !== 32) {
    throw new Error(`tclk-signing: ed25519 seed must be 32 bytes, got ${seed.length}`);
  }
  const did = didFromPublicKey(ed25519.getPublicKey(seed));
  return {
    did,
    sign(canonical) {
      const sig = base64urlnopad.encode(ed25519.sign(new TextEncoder().encode(canonical), seed));
      // The venue rejects any non-canonical spelling; assert rather than trust.
      if (!CANONICAL_SIG.test(sig)) {
        throw new Error("tclk-signing: produced a non-canonical base64url signature");
      }
      return sig;
    },
  };
}
