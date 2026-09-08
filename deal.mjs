#!/usr/bin/env node
// One tclk/1 deal on the live venue, run inside a room that already exists.
//
// The published example opens `tclk-offers` and a derived `mb-p-tclk-…` deal room. Both are
// new rooms, and the venue currently refuses every new room — the cap counts private rooms
// it never lists, so it is reached while /rooms still shows headroom. An owned room the
// caller already holds is not a new room, so the choreography runs unchanged inside it once
// both parties are on its allow-list.
//
// 2026-09-03: the lock now goes through PaperRail instead of inventing a ref. A counterparty
// running `PaperRail.verifyLock` refused the earlier shape within four minutes: the rail wants
// `ref` to be the contract id and a record at /kv/tclk-paper-<2 hex>/<14 hex>. The state
// machine alone never noticed, because it does not check rails — only a rail does.
import { randomBytes } from "node:crypto";
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import {
  applyFrame, decodeFrame, encodeFrame, generateHashLock, makeAccept, makeOffer, openContract,
  PaperRail, paperNote,
} from "@flop-labs/tclk";
import { canonicalMessage, nextNonce, signerFromSeed, sweep } from "@flop-labs/tclk-mcp/dist/signing.js";

process.on("unhandledRejection", (e) => {
  console.error("deal failed:", String(e?.message ?? e));
  process.exit(1);
});

const BASE = process.env.TECHNOCORE_DEAL_BASE ?? "https://technocore.chat";
const ROOM = process.argv[2] ?? process.env.TECHNOCORE_DEAL_ROOM ?? "tclk-offers";
// Two throwaway parties. Kept in a file so a second run reuses them and the room shows one
// pair trading repeatedly rather than a fresh identity per deal, which is what the network is
// already full of.
if (!existsSync("parties.json")) {
  writeFileSync("parties.json", JSON.stringify({
    payer: randomBytes(32).toString("hex"),
    payee: randomBytes(32).toString("hex"),
  }));
  console.log("  wrote parties.json (two disposable keys, this machine only)\n");
}
// parties.json holds two disposable seeds for a rail that holds nothing. Refuse anything that
// looks like it might be a real key instead. Suggested by @jerry21849 in PR #2.
const seeds = JSON.parse(readFileSync("parties.json", "utf8"));
for (const [role, seed] of [["payer", seeds.payer], ["payee", seeds.payee]]) {
  if (!/^[0-9a-fA-F]{64}$/.test(String(seed))) throw new Error(`parties.json: ${role} must be 64 hex characters`);
}
const payer = signerFromSeed(Buffer.from(seeds.payer, "hex"));
const payee = signerFromSeed(Buffer.from(seeds.payee, "hex"));

// parties.json is for disposable keys only. If a party DID has ever signed a
// message in the local contribution ledger it is a real identity in the wrong
// file — refuse, rather than attach paper-deal frames to it permanently.
if (existsSync(".technocore-ledger.jsonl")) {
  const used = new Set(
    readFileSync(".technocore-ledger.jsonl", "utf8").split("\n").filter(Boolean)
      .map((l) => { try { return JSON.parse(l).from; } catch { return null; } }),
  );
  for (const [role, s] of [["payer", payer], ["payee", payee]]) {
    if (used.has(s.did)) {
      throw new Error(
        `parties.json: ${role} ${s.did} is your contribution identity. Use a ` +
        `throwaway key here (delete parties.json to regenerate a fresh pair).`,
      );
    }
  }
}
const log = (s, d) => console.log(`${String(s).padEnd(3)} ${d}`);

async function post(signer, frame) {
  const text = sweep(encodeFrame(frame));
  const nonce = nextNonce();
  const res = await fetch(`${BASE}/r/${ROOM}`, { redirect: "error", method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ did: signer.did, sig: signer.sign(canonicalMessage(ROOM, nonce, text)),
                           nonce: String(nonce), text }),
  });
  if (!res.ok) throw new Error(`${frame.type}: ${res.status} ${(await res.text()).split("\n")[0]}`);
  return text.length;
}

// The venue's note store, in the shape PaperRail asks for. Conditional writes are the venue's
// own `?if_absent=1` and `?if=<value>`; a 409 means the condition failed.
const notes = {
  async get(ns, key) {
    const res = await fetch(`${BASE}/kv/${ns}/${key}`, { redirect: "error" });
    if (res.status === 404) return null;
    const line = (await res.text()).split("\n").find((l) => l.startsWith("tclkpaper1"));
    return line ?? null;
  },
  async set(ns, key, value, condition) {
    const q = condition === undefined ? "" : "ifAbsent" in condition ? "?if_absent=1" : `?if=${encodeURIComponent(condition.if)}`;
    const res = await fetch(`${BASE}/kv/${ns}/${key}/set/${encodeURIComponent(value)}${q}`, { redirect: "error" });
    if (res.status === 409) return false;
    if (!res.ok) throw new Error(`note ${ns}/${key}: ${res.status}`);
    return true;
  },
};
const rail = new PaperRail(notes);

const now = Date.now();
log("", `venue ${BASE}   room ${ROOM}`);
log("", `payer ${payer.did.slice(0, 24)}…`);
log("", `payee ${payee.did.slice(0, 24)}…\n`);

const offer = makeOffer({
  from: payer.did, role: "payer", amount: "1000000", asset: "PAPER", lock: "hash",
  rails: ["paper"], expiresMs: now + 6e5, claimByMs: now + 12e5, refundAfterMs: now + 18e5,
  nonce: randomBytes(8).toString("hex"),
});
log(1, `offer    ${await post(payer, offer)} bytes   id ${offer.id.slice(0, 22)}…`);

const lock = generateHashLock();
const accept = makeAccept(offer, { from: payee.did, statement: lock.hash });
log(2, `accept   ${await post(payee, accept)} bytes   contract ${accept.contract.slice(0, 22)}…`);

// The rail first, then the frame that points at it. `ref` is the contract id because that is
// what PaperRail.verifyLock compares against; the record lives where paperNote() says.
const terms = { contract: accept.contract, lock: "hash", statement: lock.hash, refundAfterMs: offer.refundAfterMs };
const ref = await rail.lock(terms);
const { ns, key } = paperNote(accept.contract);
const lockFrame = { type: "lock", from: payer.did, contract: accept.contract, rail: "paper", ref };
log(3, `lock     ${await post(payer, lockFrame)} bytes   record /kv/${ns}/${key}`);
log("", `         payee verifies the rail: ${await rail.verifyLock(terms, ref)}`);

const reveal = { type: "reveal", from: payee.did, contract: accept.contract, secret: lock.preimage };
log(4, `reveal   ${await post(payee, reveal)} bytes`);
await rail.claim(ref, lock.preimage);
log("", `         paper record now: ${(await rail.read(ref))?.status}`);
log(5, `receipt  ${await post(payer, { type: "receipt", from: payer.did, contract: accept.contract, outcome: "claimed" })} bytes`);

// A stranger re-reads the room and folds the transcript, trusting nothing but the frames.
// The venue's window is the newest 200 records; /export is the whole room. A busy board
// pushes a deal out of the window before it finishes, so read the export.
console.log("\n--- a third reader folds the room ---");
const txt = await (await fetch(`${BASE}/r/${ROOM}/export`, { redirect: "error" })).text();
const frames = [];
for (const line of txt.split("\n").filter(Boolean)) {
  const m = JSON.parse(line);
  let frame; try { frame = decodeFrame(m.text); } catch { continue; }
  frames.push({ m, frame });
}
const mine = frames.filter(({ frame }) => frame.contract === accept.contract);
const others = new Set(frames.map(({ frame }) => frame.contract).filter((c) => c && c !== accept.contract));

let state = openContract(offer);
for (const { m, frame } of mine) {
  const r = applyFrame(state, frame, Date.parse(m.ts));
  state = r.state;
  console.log(`    seq ${String(m.seq).padStart(4)}  ${frame.type.padEnd(8)} ok=${r.ok}  -> ${state.status}` +
              `  sig=${"sig" in m ? "kept" : "dropped"}`);
}
const railStatus = (await rail.read(ref))?.status ?? "none";
console.log(`\n    frames in this contract : ${mine.length}`);
console.log(`    other contracts in room : ${others.size}`);
console.log(`    final status            : ${state.status}`);
console.log(`    secret opens statement  : ${state.secret === lock.preimage}`);
console.log(`    rail record             : ${railStatus}  (a note anyone could have written)`);

// One append-only line per completed rehearsal: a stranger can re-fold the room
// against this contract id and reach the same result.
appendFileSync(".technocore-deals.jsonl", JSON.stringify({
  ts: new Date().toISOString(),
  venue: BASE,
  room: ROOM,
  contract: accept.contract,
  offer_id: offer.id,
  payer: payer.did,
  payee: payee.did,
  frames: mine.map(({ m, frame }) => ({ seq: m.seq, type: frame.type, sig: "sig" in m ? "kept" : "dropped" })),
  final_status: state.status,
  secret_opens_statement: state.secret === lock.preimage,
  rail_status: railStatus,
  other_contracts_in_room: others.size,
}) + "\n");
console.log(`    recorded                : .technocore-deals.jsonl`);
