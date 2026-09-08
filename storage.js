import { Config } from './config.js';
export const Settings = (() => {
    const DEFAULT = { persistHandshakes: true };
    return {
        get: () => {
            try {
                const stored = localStorage.getItem('ecp_settings');
                return stored ? { ...DEFAULT, ...JSON.parse(stored) } : DEFAULT;
            }
            catch {
                return DEFAULT;
            }
        },
        set: (settings) => {
            localStorage.setItem('ecp_settings', JSON.stringify(settings));
        },
    };
})();
export const DB = (() => {
    let dbInstance;
    const memorySessions = new Map();
    const initDB = () => new Promise((resolve, reject) => {
        const req = indexedDB.open(Config.STORAGE_DB_NAME, Config.STORAGE_DB_VERSION);
        req.onupgradeneeded = (e) => {
            const db = e.target.result;
            if (!db.objectStoreNames.contains('identity'))
                db.createObjectStore('identity', { keyPath: 'id' });
            if (!db.objectStoreNames.contains('contacts'))
                db.createObjectStore('contacts', { keyPath: 'fingerprint' });
            if (!db.objectStoreNames.contains('sessions'))
                db.createObjectStore('sessions', {
                    keyPath: 'contactFp',
                }).createIndex('conversationId', 'conversationId');
            if (!db.objectStoreNames.contains('messages'))
                db.createObjectStore('messages', { keyPath: 'id' }).createIndex('conversationId', 'conversationId');
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
    const getDB = async () => (dbInstance ??= await initDB());
    return {
        get: async (storeName, key) => {
            if (storeName === 'sessions' && !Settings.get().persistHandshakes)
                return memorySessions.get(key);
            const db = await getDB();
            return new Promise((resolve, reject) => {
                const req = db
                    .transaction(storeName, 'readonly')
                    .objectStore(storeName)
                    .get(key);
                req.onsuccess = () => resolve(req.result);
                req.onerror = () => reject(req.error);
            });
        },
        put: async (storeName, item) => {
            if (storeName === 'sessions' && !Settings.get().persistHandshakes) {
                const s = item;
                memorySessions.set(s.contactFp, s);
                return;
            }
            const db = await getDB();
            return new Promise((resolve, reject) => {
                const req = db
                    .transaction(storeName, 'readwrite')
                    .objectStore(storeName)
                    .put(item);
                req.onsuccess = () => resolve();
                req.onerror = () => reject(req.error);
            });
        },
        delete: async (storeName, key) => {
            if (storeName === 'sessions' || storeName === 'contacts')
                memorySessions.delete(key);
            const db = await getDB();
            return new Promise((resolve, reject) => {
                const req = db
                    .transaction(storeName, 'readwrite')
                    .objectStore(storeName)
                    .delete(key);
                req.onsuccess = () => resolve();
                req.onerror = () => reject(req.error);
            });
        },
        getAll: async (storeName) => {
            if (storeName === 'sessions' && !Settings.get().persistHandshakes)
                return Array.from(memorySessions.values());
            const db = await getDB();
            return new Promise((resolve, reject) => {
                const req = db
                    .transaction(storeName, 'readonly')
                    .objectStore(storeName)
                    .getAll();
                req.onsuccess = () => resolve(req.result);
                req.onerror = () => reject(req.error);
            });
        },
        deleteConversation: async (convId) => {
            const db = await getDB();
            return new Promise((resolve, reject) => {
                const tx = db.transaction('messages', 'readwrite');
                const store = tx.objectStore('messages');
                const req = store
                    .index('conversationId')
                    .openCursor(IDBKeyRange.only(convId));
                req.onsuccess = (e) => {
                    const cursor = e.target
                        .result;
                    if (cursor) {
                        store.delete(cursor.primaryKey);
                        cursor.continue();
                    }
                };
                tx.oncomplete = () => resolve();
                tx.onerror = () => reject(tx.error);
            });
        },
        getByIndex: async (storeName, indexName, indexValue) => {
            if (storeName === 'sessions' && !Settings.get().persistHandshakes) {
                for (const session of memorySessions.values())
                    if (session[indexName] === indexValue)
                        return session;
                return;
            }
            const db = await getDB();
            return new Promise((resolve, reject) => {
                const req = db
                    .transaction(storeName, 'readonly')
                    .objectStore(storeName)
                    .index(indexName)
                    .get(indexValue);
                req.onsuccess = () => resolve(req.result);
                req.onerror = () => reject(req.error);
            });
        },
        getAllByIndex: async (storeName, indexName, indexValue) => {
            if (storeName === 'sessions' && !Settings.get().persistHandshakes)
                return Array.from(memorySessions.values()).filter((session) => session[indexName] === indexValue);
            const db = await getDB();
            return new Promise((resolve, reject) => {
                const req = db
                    .transaction(storeName, 'readonly')
                    .objectStore(storeName)
                    .index(indexName)
                    .getAll(indexValue);
                req.onsuccess = () => resolve(req.result);
                req.onerror = () => reject(req.error);
            });
        },
    };
})();
//# sourceMappingURL=storage.js.map