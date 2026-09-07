import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { gcm } from '@noble/ciphers/aes.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

export const getRandomValues = <
  T extends Uint8Array<ArrayBuffer> | Uint8ClampedArray<ArrayBuffer>,
>(
  array: T,
): T => {
  const MAX_SIZE = 65536;
  if (array.length <= MAX_SIZE) return crypto.getRandomValues(array);
  for (let offset = 0; offset < array.length; )
    crypto.getRandomValues(array.subarray(offset, (offset += MAX_SIZE)));
  return array;
};

export const getRandomBytes = (size: number) =>
  getRandomValues(new Uint8Array(size));

export const randomUUID: typeof crypto.randomUUID = () => {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  const bytes = getRandomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const bth = (arr: Uint8Array) =>
    Array.from(arr)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  return `${bth(bytes.slice(0, 4))}-${bth(bytes.slice(4, 6))}-${bth(bytes.slice(6, 8))}-${bth(bytes.slice(8, 10))}-${bth(bytes.slice(10, 16))}`;
};

export const encodeBase64URL = (v: Uint8Array) =>
  typeof v.toBase64 === 'function'
    ? v.toBase64({ alphabet: 'base64url', omitPadding: true })
    : btoa(v.reduce((acc, b) => acc + String.fromCharCode(b), ''))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');

export const decodeBase64URL = (v: string) =>
  typeof Uint8Array.fromBase64 === 'function'
    ? Uint8Array.fromBase64(v, { alphabet: 'base64url' })
    : Uint8Array.from(
        atob(
          (() => {
            let s = v.replace(/-/g, '+').replace(/_/g, '/');
            while (s.length % 4) s += '=';
            return s;
          })(),
        ),
        (c) => c.charCodeAt(0),
      );

export const concatBytes = (...items: Uint8Array[]) => {
  const result = new Uint8Array(
    items.reduce((acc, { length }) => acc + length, 0),
  );
  let offset = 0;
  for (const arr of items) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
};

export const memcmp = (a: Uint8Array, b: Uint8Array) => {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
};

export { sha256 };

export const hmacSHA256 = (keyBytes: Uint8Array, msgBytes: Uint8Array) =>
  hmac(sha256, keyBytes, msgBytes);

export const hkdfSHA256 = (
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
) => hkdf(sha256, ikm, salt, info, length);

export const encryptGCM = (
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
) => gcm(key, nonce, aad).encrypt(plaintext);

export const decryptGCM = (
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
) => gcm(key, nonce, aad).decrypt(ciphertext);

export const keygenMLDSA65 = ml_dsa65.keygen;
export const signMLDSA65 = ml_dsa65.sign;
export const verifyMLDSA65 = ml_dsa65.verify;

export const keygenX25519 = x25519.keygen;
export const getSharedSecretX25519 = x25519.getSharedSecret;

export const keygenMLKEM768 = ml_kem768.keygen;
export const encapsulateMLKEM768 = ml_kem768.encapsulate;
export const decapsulateMLKEM768 = ml_kem768.decapsulate;
