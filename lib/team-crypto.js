'use strict';
// Room-scoped E2E crypto for the team relay (electron.js team-*).
// code+key live only in the out-of-band invite URL — they never cross the
// wire. Auth is an HMAC proof; payloads are AES-256-GCM, so the relay
// (host's server) sees only routing envelopes {t, from, to}.
const crypto = require('crypto');

function deriveKeys(code, key) {
  const ikm = `${code}:${key}`;
  const authKey = crypto.hkdfSync('sha256', ikm, 'prom-team-v2', 'auth', 32);
  const encKey  = crypto.hkdfSync('sha256', ikm, 'prom-team-v2', 'enc', 32);
  return { authKey: Buffer.from(authKey), encKey: Buffer.from(encKey) };
}

// Proof of room secret knowledge — replaces sending `key` in hello.
function helloMac(authKey, code, name) {
  return crypto.createHmac('sha256', authKey).update(`${code}|${name}`).digest('base64url');
}
function macOk(authKey, code, name, mac) {
  try { return crypto.timingSafeEqual(Buffer.from(helloMac(authKey, code, name)),
                                      Buffer.from(String(mac || ''))); }
  catch (e) { return false; }
}

function encrypt(encKey, obj, seq) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', encKey, iv);
  // seq is authenticated via AAD — the relay can't strip it without failing the tag
  const wire = JSON.stringify({ s: seq >>> 0, d: obj });
  const ct = Buffer.concat([c.update(wire, 'utf8'), c.final()]);
  return { e2: 1, iv: iv.toString('base64url'), ct: ct.toString('base64url'),
           tag: c.getAuthTag().toString('base64url') };
}
// No legacy passthrough: anything that isn't a well-formed e2 envelope is
// dropped — a downgrade to plaintext is treated as tampering.
// seenSeq tracks the highest accepted seq per sender to reject replays.
function decrypt(encKey, p, seenSeq) {
  try {
    if (!p || p.e2 !== 1) return null;
    const d = crypto.createDecipheriv('aes-256-gcm', encKey, Buffer.from(p.iv, 'base64url'));
    d.setAuthTag(Buffer.from(p.tag, 'base64url'));
    const wire = JSON.parse(Buffer.concat([d.update(Buffer.from(p.ct, 'base64url')), d.final()]).toString('utf8'));
    if (typeof wire.s !== 'number' || wire.d === undefined) return null;
    if (seenSeq) {                                        // replay protection
      if (wire.s <= seenSeq.last) return null;
      seenSeq.last = wire.s;
    }
    return wire.d;
  } catch (e) { return null; }
}

// ── v3: per-member ephemeral X25519 + host-rotated room key ──────────────
// Each member publishes an ephemeral X25519 pubkey in hello, bound to the
// room-secret HMAC (relay can't MITM the key exchange). The room key is a
// fresh random per session, rotated on every membership change and delivered
// under pairwise ECDH keys — a departed member can't read post-leave traffic,
// and member↔member DMs are unreadable to the relay and other members.

function genKeyPair() {
  const kp = crypto.generateKeyPairSync('x25519');
  return { priv: kp.privateKey, pub: kp.publicKey.export({ format: 'jwk' }).x };
}
function pubKeyFromX(x) {
  return crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x }, format: 'jwk' });
}
function pairKey(priv, theirPubX) {
  const shared = crypto.diffieHellman({ privateKey: priv, publicKey: pubKeyFromX(theirPubX) });
  return Buffer.from(crypto.hkdfSync('sha256', shared, 'prom-team-v3', 'pair', 32));
}
const newRoomKey = () => crypto.randomBytes(32);

// MAC binds the ECDH pubkey to the room-secret proof — a relay swapping the
// pubkey fails verification.
const helloMacV3 = (authKey, code, name, pubX) =>
  crypto.createHmac('sha256', authKey).update(`${code}|${name}|${pubX}`).digest('base64url');
const macOkV3 = (authKey, code, name, pubX, mac) => {
  try { return crypto.timingSafeEqual(Buffer.from(helloMacV3(authKey, code, name, pubX)),
                                      Buffer.from(String(mac || ''))); }
  catch (e) { return false; }
};

module.exports = { deriveKeys, helloMac, macOk, encrypt, decrypt,
                   genKeyPair, pairKey, newRoomKey, helloMacV3, macOkV3 };
