import { Config } from './config.js';
import type {
  Identity,
  Contact,
  Session,
  Message,
  AppSettings,
} from './types.js';

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
    set: (settings: AppSettings): void => {
      localStorage.setItem('ecp_settings', JSON.stringify(settings));
    },
  };
})();

type StoreName = 'identity' | 'contacts' | 'sessions' | 'messages';
type StoreEntity = {
  identity: Identity;
  contacts: Contact;
  sessions: Session;
  messages: Message;
};
type StorePrimaryKey = {
  identity: string;
  contacts: string;
  sessions: string;
  messages: string;
};

export const DB = (() => {
  let dbInstance: IDBDatabase | undefined;
  const memorySessions = new Map<string, Session>();

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
        if (!db.objectStoreNames.contains('contacts'))
          db.createObjectStore('contacts', { keyPath: 'fingerprint' });
        if (!db.objectStoreNames.contains('sessions'))
          db.createObjectStore('sessions', { keyPath: 'contactFp' });
        if (!db.objectStoreNames.contains('messages'))
          db.createObjectStore('messages', { keyPath: 'id' }).createIndex(
            'conversationId',
            'conversationId',
          );
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });

  const getDB = async () => (dbInstance ??= await initDB());

  return {
    get: async <S extends StoreName>(storeName: S, key: StorePrimaryKey[S]) => {
      if (storeName === 'sessions' && !Settings.get().persistHandshakes)
        return memorySessions.get(key) as StoreEntity[S] | undefined;
      const db = await getDB();
      return new Promise<StoreEntity[S] | undefined>((resolve, reject) => {
        const req = db
          .transaction(storeName, 'readonly')
          .objectStore(storeName)
          .get(key);
        req.onsuccess = () => {
          let result = req.result as StoreEntity[S] | undefined;
          if (storeName === 'contacts' && result) {
            (result as Contact).archived =
              (result as Contact).archived || false;
            (result as Contact).lastReadTimestamp =
              (result as Contact).lastReadTimestamp || 0;
          }
          resolve(result);
        };
        req.onerror = () => reject(req.error);
      });
    },

    put: async <S extends StoreName>(storeName: S, item: StoreEntity[S]) => {
      if (storeName === 'sessions' && !Settings.get().persistHandshakes) {
        const s = item as Session;
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

    delete: async <S extends StoreName>(
      storeName: S,
      key: StorePrimaryKey[S],
    ) => {
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

    getAll: async <S extends StoreName>(storeName: S) => {
      if (storeName === 'sessions' && !Settings.get().persistHandshakes)
        return Array.from(memorySessions.values()) as StoreEntity[S][];
      const db = await getDB();
      return new Promise<StoreEntity[S][]>((resolve, reject) => {
        const req = db
          .transaction(storeName, 'readonly')
          .objectStore(storeName)
          .getAll();
        req.onsuccess = () => resolve(req.result as StoreEntity[S][]);
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
          const cursor = (e.target as IDBRequest)
            .result as IDBCursorWithValue | null;
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
