import { Config } from './config.js';
import type { ChannelSession, AppSettings } from './types.js';

export const Settings = (() => {
  const DEFAULT: AppSettings = { persistHandshakes: true };
  return {
    get: (): AppSettings => {
      try {
        const stored = localStorage.getItem('ecp_settings');
        return stored ? { ...DEFAULT, ...JSON.parse(stored) } : DEFAULT;
      } catch {
        return DEFAULT;
      }
    },
    set: (settings: AppSettings) => {
      localStorage.setItem('ecp_settings', JSON.stringify(settings));
    },
  };
})();

export const DB = (() => {
  let dbInstance: IDBDatabase | undefined;
  const memorySessions = new Map<string, ChannelSession>();

  const initDB = () =>
    new Promise<IDBDatabase>((resolve, reject) => {
      const req = indexedDB.open(
        Config.STORAGE_DB_NAME,
        Config.STORAGE_DB_VERSION,
      );
      req.onupgradeneeded = (e) => {
        const db = (e.target as IDBOpenDBRequest).result;
        if (!db.objectStoreNames.contains('identity'))
          db.createObjectStore('identity', { keyPath: 'id' });
        if (!db.objectStoreNames.contains('sessions'))
          db.createObjectStore('sessions', { keyPath: 'contactFp' });
        if (!db.objectStoreNames.contains('messages'))
          db.createObjectStore('messages', {
            keyPath: 'messageId',
          }).createIndex('conversationId', 'conversationId', { unique: false });
        if (!db.objectStoreNames.contains('contacts'))
          db.createObjectStore('contacts', { keyPath: 'fingerprint' });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });

  const getDB = async () => (dbInstance ??= await initDB());

  return {
    get: async <T>(storeName: string, key: string) => {
      if (storeName === 'sessions' && !Settings.get().persistHandshakes)
        return memorySessions.get(key) as T | undefined;
      const db = await getDB();
      return new Promise<T | undefined>((resolve, reject) => {
        const req = db
          .transaction(storeName, 'readonly')
          .objectStore(storeName)
          .get(key);
        req.onsuccess = () => {
          if (storeName === 'contacts' && req.result) {
            req.result.archived = req.result.archived || false;
            req.result.lastReadTimestamp = req.result.lastReadTimestamp || 0;
          }
          resolve(req.result);
        };
        req.onerror = () => reject(req.error);
      });
    },
    put: async (storeName: string, item: unknown) => {
      if (storeName === 'sessions' && !Settings.get().persistHandshakes) {
        const s = item as ChannelSession;
        memorySessions.set(s.contactFp, s);
        return;
      }
      const db = await getDB();
      return new Promise<void>((resolve, reject) => {
        const req = db
          .transaction(storeName, 'readwrite')
          .objectStore(storeName)
          .put(item);
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
      });
    },
    delete: async (storeName: string, key: string) => {
      if (storeName === 'sessions' || storeName === 'contacts')
        memorySessions.delete(key);
      const db = await getDB();
      return new Promise<void>((resolve, reject) => {
        const req = db
          .transaction(storeName, 'readwrite')
          .objectStore(storeName)
          .delete(key);
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
      });
    },
    getAll: async <T>(storeName: string) => {
      if (storeName === 'sessions' && !Settings.get().persistHandshakes)
        return Array.from(memorySessions.values()) as T[];
      const db = await getDB();
      return new Promise<T[]>((resolve, reject) => {
        const req = db
          .transaction(storeName, 'readonly')
          .objectStore(storeName)
          .getAll();
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    },
    deleteConversation: async (convId: string) => {
      const db = await getDB();
      return new Promise<void>((resolve, reject) => {
        const tx = db.transaction('messages', 'readwrite');
        const store = tx.objectStore('messages');
        const req = store
          .index('conversationId')
          .openCursor(IDBKeyRange.only(convId));
        req.onsuccess = (e) => {
          const cursor = (e.target as IDBRequest).result as IDBCursorWithValue;
          if (cursor) {
            store.delete(cursor.primaryKey);
            cursor.continue();
          }
        };
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    },
  };
})();
