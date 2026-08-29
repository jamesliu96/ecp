import { sha256, hmac, hkdf } from '@noble/hashes/webcrypto.js';
import { gcm } from '@noble/ciphers/webcrypto.js';
import { x25519 } from '@noble/curves/webcrypto.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';

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
  ('toBase64' in v && typeof v.toBase64 === 'function'
    ? v.toBase64()
    : btoa(String.fromCharCode(...v))
  )
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

export const decodeBase64URL = (v: string) => {
  v = v.replace(/-/g, '+').replace(/_/g, '/');
  while (v.length % 4) v += '=';
  return 'fromBase64' in Uint8Array &&
    typeof Uint8Array.fromBase64 === 'function'
    ? Uint8Array.fromBase64(v)
    : Uint8Array.from(atob(v), (c) => c.charCodeAt(0));
};

export const concatBytes = (...args: Uint8Array[]) => {
  const result = new Uint8Array(
    args.reduce((acc, { length }) => acc + length, 0),
  );
  let offset = 0;
  for (const item of args) {
    result.set(item, offset);
    offset += item.length;
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

export const keygenMLDSA87 = ml_dsa87.keygen;
export const signMLDSA87 = ml_dsa87.sign;
export const verifyMLDSA87 = ml_dsa87.verify;

const X25519 = (await x25519.isSupported())
  ? x25519
  : (await import('@noble/curves/ed25519.js')).x25519;
export const keygenX25519 = X25519.keygen;
export const getSharedSecretX25519 = X25519.getSharedSecret;

export const keygenMLKEM1024 = ml_kem1024.keygen;
export const encapsulateMLKEM1024 = ml_kem1024.encapsulate;
export const decapsulateMLKEM1024 = ml_kem1024.decapsulate;
