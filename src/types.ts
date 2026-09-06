export interface Identity {
  id: string;
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
