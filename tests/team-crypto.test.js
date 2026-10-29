'use strict';
// E2E crypto for the team relay — key derivation, hello MAC, payload AEAD.
const test = require('node:test');
const assert = require('node:assert');
const { deriveKeys, helloMac, macOk, encrypt, decrypt,
        genKeyPair, pairKey, newRoomKey, helloMacV3, macOkV3 } = require('../lib/team-crypto.js');

const A = deriveKeys('ABC123', 'k3y-x9z');
const B = deriveKeys('ABC123', 'k3y-x9z');           // same invite → same keys
const C = deriveKeys('ABC123', 'wrong');             // different secret

test('keys derive deterministically from code+key', () => {
  assert.deepEqual(A.authKey, B.authKey);
  assert.deepEqual(A.encKey, B.encKey);
  assert.notDeepEqual(A.encKey, C.encKey);
  assert.equal(A.encKey.length, 32);
});

test('hello MAC proves secret knowledge without transmitting it', () => {
  const mac = helloMac(A.authKey, 'ABC123', 'alice');
  assert.ok(macOk(A.authKey, 'ABC123', 'alice', mac));
  assert.ok(!macOk(C.authKey, 'ABC123', 'alice', mac));      // wrong key
  assert.ok(!macOk(A.authKey, 'ABC123', 'mallory', mac));    // wrong name
  assert.ok(!macOk(A.authKey, 'ZZZZZZ', 'alice', mac));      // wrong code
  assert.ok(!macOk(A.authKey, 'ABC123', 'alice', 'garbage'));
});

test('payload roundtrip; wrong key or tampering is dropped', () => {
  const msg = { kind: 'save', p: 'src/a.js', content: 'const x=1;' };
  const enc = encrypt(A.encKey, msg, 0);
  assert.equal(enc.e2, 1);
  assert.ok(!JSON.stringify(enc).includes('const x'));       // opaque envelope
  assert.deepEqual(decrypt(A.encKey, enc), msg);
  assert.deepEqual(decrypt(B.encKey, enc), msg);             // peer with same invite
  assert.strictEqual(decrypt(C.encKey, enc), null);          // wrong room secret
  const bad = { ...enc, ct: enc.ct.slice(0, -4) + 'AAAA' };
  assert.strictEqual(decrypt(A.encKey, bad), null);          // GCM tag catches it
});

test('no downgrade: plaintext/legacy payloads are dropped', () => {
  assert.strictEqual(decrypt(A.encKey, { kind: 'chat', text: 'hola' }), null);
  assert.strictEqual(decrypt(A.encKey, 'just a string'), null);
});

test('replay protection: stale or repeated seq is rejected', () => {
  const seen = { last: -1 };
  const m1 = encrypt(A.encKey, { n: 1 }, 0);
  const m2 = encrypt(A.encKey, { n: 2 }, 1);
  assert.deepEqual(decrypt(A.encKey, m2, seen), { n: 2 });
  assert.strictEqual(decrypt(A.encKey, m2, seen), null);     // replay of same seq
  assert.strictEqual(decrypt(A.encKey, m1, seen), null);     // older seq
});

test('v3: X25519 pairs agree on the same pairwise key', () => {
  const a = genKeyPair(), b = genKeyPair(), c = genKeyPair();
  assert.deepEqual(pairKey(a.priv, b.pub), pairKey(b.priv, a.pub));   // ECDH agreement
  assert.notDeepEqual(pairKey(a.priv, b.pub), pairKey(a.priv, c.pub)); // different peer
  // pairwise DM opaque under room key, and vice versa
  const dm = encrypt(pairKey(a.priv, b.pub), { kind: 'dm', text: 'shh' }, 0);
  assert.strictEqual(decrypt(c.encKey /* any room key */, dm), null);
  assert.deepEqual(decrypt(pairKey(b.priv, a.pub), dm), { kind: 'dm', text: 'shh' });
});

test('v3: hello MAC binds the ECDH pubkey — relay key-swap fails', () => {
  const me = genKeyPair(), evil = genKeyPair();
  const mac = helloMacV3(A.authKey, 'ABC123', 'alice', me.pub);
  assert.ok(macOkV3(A.authKey, 'ABC123', 'alice', me.pub, mac));
  assert.ok(!macOkV3(A.authKey, 'ABC123', 'alice', evil.pub, mac));   // swapped pub
  assert.ok(!macOkV3(C.authKey, 'ABC123', 'alice', me.pub, mac));     // wrong secret
});

test('v3: room key rotation invalidates old key', () => {
  const r1 = newRoomKey(), r2 = newRoomKey();
  assert.notDeepEqual(r1, r2);
  const enc = encrypt(r1, { kind: 'chat', text: 'x' }, 0);
  assert.strictEqual(decrypt(r2, enc), null);    // post-rotation key can't open pre-rotation
  assert.deepEqual(decrypt(r1, enc), { kind: 'chat', text: 'x' });
});
