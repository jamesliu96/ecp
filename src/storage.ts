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

type StoreName = keyof StoreEntity;
type StoreEntity = {
  identity: Identity;
  contacts: Contact;
  sessions: Session;
  messages: Message;
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
          db.createObjectStore('sessions', {
            keyPath: 'contactFp',
          }).createIndex('conversationId', 'conversationId');
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
    get: async <S extends StoreName>(storeName: S, key: string) => {
      if (storeName === 'sessions' && !Settings.get().persistHandshakes) {
        const val = memorySessions.get(key);
        return val ? (structuredClone(val) as StoreEntity[S]) : undefined;
      }
      const db = await getDB();
      return new Promise<StoreEntity[S] | undefined>((resolve, reject) => {
        const req = db
          .transaction(storeName, 'readonly')
          .objectStore(storeName)
          .get(key);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    },

    put: async <S extends StoreName>(storeName: S, item: StoreEntity[S]) => {
      if (storeName === 'sessions' && !Settings.get().persistHandshakes) {
        memorySessions.set(
          (item as Session).contactFp,
          structuredClone(item) as Session,
        );
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

    delete: async <S extends StoreName>(storeName: S, key: string) => {
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
        return Array.from(memorySessions.values()).map((v) =>
          structuredClone(v),
        ) as StoreEntity[S][];
      const db = await getDB();
      return new Promise<StoreEntity[S][]>((resolve, reject) => {
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

    getByIndex: async <S extends StoreName, K extends keyof StoreEntity[S]>(
      storeName: S,
      indexName: K,
      indexValue: StoreEntity[S][K],
    ) => {
      if (storeName === 'sessions' && !Settings.get().persistHandshakes) {
        for (const session of memorySessions.values())
          if (session[indexName as keyof Session] === indexValue)
            return structuredClone(session) as StoreEntity[S];
        return;
      }
      const db = await getDB();
      return new Promise<StoreEntity[S] | undefined>((resolve, reject) => {
        const req = db
          .transaction(storeName, 'readonly')
          .objectStore(storeName)
          .index(indexName as string)
          .get(indexValue as IDBValidKey);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    },

    getAllByIndex: async <S extends StoreName, K extends keyof StoreEntity[S]>(
      storeName: S,
      indexName: K,
      indexValue: StoreEntity[S][K],
    ) => {
      if (storeName === 'sessions' && !Settings.get().persistHandshakes)
        return Array.from(memorySessions.values())
          .filter(
            (session) => session[indexName as keyof Session] === indexValue,
          )
          .map((v) => structuredClone(v)) as StoreEntity[S][];
      const db = await getDB();
      return new Promise<StoreEntity[S][]>((resolve, reject) => {
        const req = db
          .transaction(storeName, 'readonly')
          .objectStore(storeName)
          .index(indexName as string)
          .getAll(indexValue as IDBValidKey);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    },
  };
})();
