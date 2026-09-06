const CACHE_NAME = 'ecp-v1';
// sha256:cafa174bad7643bd88c21d49e1ab7b0c4870be9bb4c2ce9ee17828e029683d62
const CACHE = [
  '/',
  '/index.html',
  '/favicon.ico',
  '/icon-192.png',
  '/icon-512.png',
  '/manifest.json',
  '/main.css',
  '/codec.js',
  '/codec.js.map',
  '/config.js',
  '/config.js.map',
  '/crypto.js',
  '/crypto.js.map',
  '/identity.js',
  '/identity.js.map',
  '/main.js',
  '/main.js.map',
  '/ratchet.js',
  '/ratchet.js.map',
  '/storage.js',
  '/storage.js.map',
  '/types.js',
  '/types.js.map',
  '/vendor/@noble/post-quantum/_crystals.js',
  '/vendor/@noble/post-quantum/falcon.js',
  '/vendor/@noble/post-quantum/hybrid.js',
  '/vendor/@noble/post-quantum/index.js',
  '/vendor/@noble/post-quantum/ml-dsa.js',
  '/vendor/@noble/post-quantum/ml-kem.js',
  '/vendor/@noble/post-quantum/slh-dsa.js',
  '/vendor/@noble/post-quantum/utils.js',
  '/vendor/@noble/post-quantum/webcrypto.js',
  '/vendor/@noble/hashes/_blake.js',
  '/vendor/@noble/hashes/_md.js',
  '/vendor/@noble/hashes/_u64.js',
  '/vendor/@noble/hashes/argon2.js',
  '/vendor/@noble/hashes/blake1.js',
  '/vendor/@noble/hashes/blake2.js',
  '/vendor/@noble/hashes/blake3.js',
  '/vendor/@noble/hashes/eskdf.js',
  '/vendor/@noble/hashes/hkdf.js',
  '/vendor/@noble/hashes/hmac.js',
  '/vendor/@noble/hashes/index.js',
  '/vendor/@noble/hashes/legacy.js',
  '/vendor/@noble/hashes/pbkdf2.js',
  '/vendor/@noble/hashes/scrypt.js',
  '/vendor/@noble/hashes/sha2.js',
  '/vendor/@noble/hashes/sha3-addons.js',
  '/vendor/@noble/hashes/sha3.js',
  '/vendor/@noble/hashes/utils.js',
  '/vendor/@noble/hashes/webcrypto.js',
  '/vendor/@noble/curves/bls12-381.js',
  '/vendor/@noble/curves/bn254.js',
  '/vendor/@noble/curves/ed25519.js',
  '/vendor/@noble/curves/ed448.js',
  '/vendor/@noble/curves/index.js',
  '/vendor/@noble/curves/misc.js',
  '/vendor/@noble/curves/nist.js',
  '/vendor/@noble/curves/secp256k1.js',
  '/vendor/@noble/curves/utils.js',
  '/vendor/@noble/curves/webcrypto.js',
  '/vendor/@noble/curves/abstract/bls.js',
  '/vendor/@noble/curves/abstract/curve.js',
  '/vendor/@noble/curves/abstract/der.js',
  '/vendor/@noble/curves/abstract/edwards.js',
  '/vendor/@noble/curves/abstract/fft.js',
  '/vendor/@noble/curves/abstract/frost.js',
  '/vendor/@noble/curves/abstract/hash-to-curve.js',
  '/vendor/@noble/curves/abstract/modular.js',
  '/vendor/@noble/curves/abstract/montgomery.js',
  '/vendor/@noble/curves/abstract/oprf.js',
  '/vendor/@noble/curves/abstract/poseidon.js',
  '/vendor/@noble/curves/abstract/tower.js',
  '/vendor/@noble/curves/abstract/weierstrass.js',
  '/vendor/@noble/ciphers/_arx.js',
  '/vendor/@noble/ciphers/_poly1305.js',
  '/vendor/@noble/ciphers/_polyval.js',
  '/vendor/@noble/ciphers/aes.js',
  '/vendor/@noble/ciphers/chacha.js',
  '/vendor/@noble/ciphers/ff1.js',
  '/vendor/@noble/ciphers/index.js',
  '/vendor/@noble/ciphers/salsa.js',
  '/vendor/@noble/ciphers/utils.js',
  '/vendor/@noble/ciphers/webcrypto.js',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => cache.addAll(CACHE))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((cacheNames) =>
        Promise.all(
          cacheNames.map((cacheName) =>
            cacheName !== CACHE_NAME ? caches.delete(cacheName) : false,
          ),
        ),
      )
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  event.respondWith(caches.match(req).then((resp) => resp ?? fetch(req)));
});
