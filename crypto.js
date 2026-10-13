// Nudge vault crypto for the browser (and Node 20+). Same format as app/.../sync/VaultCrypto.kt
// Key: PBKDF2-HMAC-SHA256(UTF-8 passphrase, salt, 600k) -> AES-256-GCM, 12-byte IV.
// Envelope: {"v":1,"iv":"<b64>","ct":"<b64 ciphertext+tag>"}

export const ITERATIONS = 600000;
export const CHECK_TEXT = "nudge-vault-ok";

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

export const b64 = (bytes) => {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s);
};
export const unb64 = (text) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));

export function newSalt() {
  return globalThis.crypto.getRandomValues(new Uint8Array(16));
}

/** Returns a non-extractable AES-GCM CryptoKey. */
export async function deriveKey(passphrase, salt, iterations = ITERATIONS) {
  const base = await subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encrypt(key, plainText) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plainText));
  return JSON.stringify({ v: 1, iv: b64(iv), ct: b64(ct) });
}

/** Throws if the passphrase is wrong or the data was changed. */
export async function decrypt(key, envelope) {
  const { iv, ct } = JSON.parse(envelope);
  const plain = await subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, key, unb64(ct));
  return dec.decode(plain);
}
