import { readdirSync, statSync, writeFileSync } from 'fs';
import { join, basename, extname } from 'path';

/** @param {string} dir */
function walkVendor(dir, base = '') {
  /** @type {string[]} */
  let results = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const stat = statSync(full);
    if (stat.isDirectory())
      results = results.concat(walkVendor(full, base + name + '/'));
    else if (name.endsWith('.js')) results.push(`/vendor/${base}${name}`);
  }
  return results;
}

/** @param {string} dir */
function walkSrcTs(dir, base = '') {
  /** @type {string[]} */
  let results = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      results = results.concat(walkSrcTs(full, base + name + '/'));
    } else if (extname(name) === '.ts') {
      const file = basename(name, '.ts');
      results.push(`/${base}${file}.js`, `/${base}${file}.js.map`);
    }
  }
  return results;
}

const staticAssets = [
  '/',
  '/index.html',
  '/favicon.ico',
  '/icon-192.png',
  '/icon-512.png',
  '/manifest.json',
  '/main.css',
];

const srcJsAssets = walkSrcTs('src');

const vendorAssets = walkVendor('vendor/@noble', '@noble/');

const allAssets = [...staticAssets, ...srcJsAssets, ...vendorAssets];

const assetsStr = '[\n' + allAssets.map((s) => `  '${s}',`).join('\n') + '\n]';

const swTemplate = `const CACHE_NAME = 'ecp-v1';
const CACHE = ${assetsStr};

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
          cacheNames.map((cacheName) => {
            if (cacheName !== CACHE_NAME) return caches.delete(cacheName);
          }),
        ),
      )
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  event.respondWith(
    caches.match(req).then((cachedResponse) => {
      if (cachedResponse) return cachedResponse;
      return fetch(req);
    }),
  );
});
`;

writeFileSync('sw.js', swTemplate);
