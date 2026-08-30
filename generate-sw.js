import { createReadStream } from 'node:fs';
import { readdir, writeFile } from 'node:fs/promises';
import { join, parse } from 'node:path';
import { createHash } from 'node:crypto';

/**
 * @param {string} dir
 * @param {RegExp} pattern
 * @param {(entry: { name: string, base: string, path: string }) => string[]} mapFn
 */
async function collectAssets(dir, pattern, mapFn) {
  const entries = await readdir(dir, { recursive: true, withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile() && pattern.test(entry.name))
    .flatMap((entry) => {
      const fileBase = parse(entry.name).name;
      const relativePath = join(entry.parentPath ?? dir, entry.name);
      return mapFn({ name: entry.name, base: fileBase, path: relativePath });
    });
}

/** @param {string[]} assets */
async function computeFullHash(assets) {
  const hash = createHash('sha256');
  for (const asset of assets) {
    const filePath = asset.replace(/^\//, '');
    if (!filePath) continue;
    try {
      for await (const chunk of createReadStream(filePath)) hash.update(chunk);
    } catch {}
  }
  return hash.digest('hex');
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

const srcAssets = await collectAssets('src', /\.ts$/, ({ path }) => {
  const jsPath = `/${path.substring('src/'.length).replace(/\.ts$/, '.js')}`;
  return [jsPath, `${jsPath}.map`];
});

const vendorAssets = await collectAssets(
  'vendor/@noble',
  /\.js$/,
  ({ path }) => [`/${path}`],
);

const allAssets = [...staticAssets, ...srcAssets, ...vendorAssets];
const fullHashHex = await computeFullHash(allAssets);

const formattedAssets = allAssets.map((asset) => `  '${asset}',`).join('\n');

const swTemplate = `const CACHE_NAME = 'ecp-v1';
// sha256:${fullHashHex}
const CACHE = [
${formattedAssets}
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
`;

await writeFile('sw.js', swTemplate, 'utf8');
