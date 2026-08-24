#!/usr/bin/env node
// Fixed vectors for the three things a Technocore client must get exactly right.
// Cross-checked against the reference server (github.com/flop-labs/technocore-chat):
// src/didkey.py (DID + verification), src/store.py clean_text (the sweep),
// src/app.py _signer (the canonical string).  Run: node test/verify.mjs
import { sweep, verifySig, didFromSeed, signCanonical } from '../bin/tc.mjs';

let pass = 0, fail = 0;
const eq = (name, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  ok ? pass++ : fail++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${ok ? '' : `\n     got:  ${JSON.stringify(got)}\n     want: ${JSON.stringify(want)}`}`);
};

// --- 1. did:key derivation from a fixed seed (multicodec ed25519-pub = 0xed 0x01) ---
const SEED = Buffer.alloc(32, 7); // 32 bytes of 0x07
const { did, priv } = didFromSeed(SEED);
eq('did:key from fixed seed', did, 'did:key:z6MkvDqGT54cXesYGvABpF1UapVNwjCqRcafi4Px6Thv5T3Z');
eq('did:key length is 56 chars', did.length, 56);

// --- 2. the single-line sweep (Cc/Cf/Cs/Co/Zl/Zp -> space, then trim) ---
eq('sweep: zero-width space', sweep('a​b'), 'a b');
eq('sweep: bidi override (Trojan Source)', sweep('a‮b'), 'a b');
eq('sweep: soft hyphen', sweep('a­b'), 'a b');
eq('sweep: newline', sweep('a\nb'), 'a b');
eq('sweep: U+2028 line separator', sweep('a b'), 'a b');
eq('sweep: Unicode tag char (U+E0041)', sweep('a\u{E0041}b'), 'a b');
eq('sweep: trims the ends', sweep('  hi  '), 'hi');
eq('sweep: keeps interior runs', sweep('a   b'), 'a   b');
eq('sweep: NBSP is Zs, survives', sweep('a b'), 'a b');
try { sweep('​​'); eq('sweep: all-invisible rejected', 'no throw', 'throw'); }
catch { pass++; console.log('ok   sweep: all-invisible input is rejected'); }

// --- 3. the canonical string and signature (room|nonce|text, post-sweep) ---
const canonical = 'lobby|1|hello world';
const sig = signCanonical(priv, canonical);
eq('signature is 86 unpadded base64url chars', [sig.length, /^[A-Za-z0-9_-]+$/.test(sig)], [86, true]);
eq('signature verifies', verifySig(did, sig, canonical), true);
eq('tampered message is refused', verifySig(did, sig, canonical + 'x'), false);
eq('wrong room is refused', verifySig(did, sig, 'meta|1|hello world'), false);
eq('replayed nonce is a different message', verifySig(did, sig, 'lobby|2|hello world'), false);

// Ed25519 is deterministic, so this is the exact byte string the reference signer
// (cryptography.Ed25519PrivateKey, as used by scripts/sign.py) produces for the same
// seed and canonical string. Equality here is parity with the server, not just internal
// consistency: a client that agrees with itself but not with src/didkey.py is broken.
eq('byte-identical to the reference signer', sig,
  'fVc7wd0O78uyyk90jD7bkVmLIPeQWyrHQ2Qf9HVGKQzrImnWDUkFdRu8EvO7oiYyM7Bq90Wp8-KufIojB5MBCA');

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
