export interface Identity {
  id: string;
  ecSk: Uint8Array;
  ecPk: Uint8Array;
  dsaSk: Uint8Array;
  dsaPk: Uint8Array;
  dhSk: Uint8Array;
  dhPk: Uint8Array;
  kemSk: Uint8Array;
  kemPk: Uint8Array;
}

export interface Contact {
  fingerprint: string;
  bundle: string;
  name: string;
  verified: boolean;
  archived: boolean;
  lastReadTimestamp: number;
}

export interface Session {
  contactFp: string;
  version: number;
  conversationID: string;
  peerIdentity: string;
  DHs: { sk: Uint8Array; pk: Uint8Array };
  DHr?: { pk: Uint8Array };
  RK: Uint8Array;
  CKs?: Uint8Array;
  CKr?: Uint8Array;
  Ns: number;
  Nr: number;
  PN: number;
  SK?: Uint8Array;
  state: 'HANDSHAKE_SENT' | 'HANDSHAKE_RECEIVED' | 'ESTABLISHED';
  lastRespPacket?: string;
  /** Keyed by `${dhPubBase64}_${sequenceNumber}` containing derived 32-byte MK */
  skippedKeys?: Record<string, string>;
}

export interface Message {
  id: string;
  conversationId: string;
  isMe: boolean;
  text: string;
  timestamp: number;
}

export interface AppSettings {
  persistHandshakes: boolean;
}
