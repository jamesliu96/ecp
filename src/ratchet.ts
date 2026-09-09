import { buildHeader, parseHeader } from './codec.js';
import { Config } from './config.js';
import {
  encodeBase64URL,
  decodeBase64URL,
  concatBytes,
  memcmp,
  sha256,
  hkdfSHA256,
  hmacSHA256,
  encryptGCM,
  decryptGCM,
  encapsulateMLKEM1024,
  decapsulateMLKEM1024,
  keygenX25519,
  getSharedSecretX25519,
  signComposite,
  verifyComposite,
  constantTimeCompare,
} from './crypto.js';
import {
  getLocalFingerprint,
  getLocalIdentity,
  serializeIdentityPublic,
  parseIdentityPublic,
  calculateFingerprint,
} from './identity.js';
import { DB } from './storage.js';
import type { Session } from './types.js';

export async function CreateInit(contactFp: string, plaintextStr: string) {
  const localFp = await getLocalFingerprint();
  if (contactFp === localFp)
    throw new Error(
      'Self-messaging prohibited: cannot initiate handshake with self.',
    );

  const local = await getLocalIdentity();
  const contact = await DB.get('contacts', contactFp);
  if (!contact) throw new Error('Peer context missing');

  const localPubBytes = serializeIdentityPublic(local);
  const peerPubBytes = decodeBase64URL(contact.bundle);
  const peerId = parseIdentityPublic(peerPubBytes);

  const ekKP = keygenX25519();
  const kemRes = encapsulateMLKEM1024(peerId.kemPk);
  const dh1 = getSharedSecretX25519(ekKP.secretKey, peerId.dhPk);

  let SK: Uint8Array;
  try {
    SK = hkdfSHA256(
      concatBytes(
        new TextEncoder().encode('ECP-INIT-v1'),
        dh1,
        kemRes.sharedSecret,
      ),
      new Uint8Array(32),
      new TextEncoder().encode(''),
      32,
    );
  } finally {
    dh1.fill(0);
    kemRes.sharedSecret.fill(0);
  }

  const sigInput = concatBytes(
    new TextEncoder().encode('ECP-INIT-v1'),
    localPubBytes,
    peerPubBytes,
    ekKP.publicKey,
    kemRes.cipherText,
  );
  const sig = signComposite(sigInput, local.ecSk, local.dsaSk);

  const MK0 = hkdfSHA256(
    SK,
    new Uint8Array(32),
    new TextEncoder().encode('ECP-INIT-MESSAGE-v1'),
    32,
  );
  const aesKeyInit = hkdfSHA256(
    MK0,
    new Uint8Array(32),
    new TextEncoder().encode('ECP-AES256GCM-v1'),
    32,
  );
  const nonceInitBytes = hmacSHA256(
    MK0,
    new TextEncoder().encode('ECP-INIT-NONCE'),
  );

  const payloadFixed = concatBytes(
    localPubBytes,
    peerPubBytes,
    ekKP.publicKey,
    kemRes.cipherText,
    sig,
  );
  const ptextEnc = new TextEncoder().encode(plaintextStr);
  const header = buildHeader(
    Config.PACKET_TYPES.INIT,
    payloadFixed.length + ptextEnc.length + 16,
  );
  const aad = concatBytes(header, payloadFixed);

  let ciphertext: Uint8Array;
  try {
    ciphertext = encryptGCM(
      aesKeyInit,
      nonceInitBytes.slice(0, 12),
      ptextEnc,
      aad,
    );
  } finally {
    aesKeyInit.fill(0);
    MK0.fill(0);
  }

  const fullPacket = concatBytes(header, payloadFixed, ciphertext);
  const cmp = memcmp(localPubBytes, peerPubBytes);
  const convIdHash = sha256(
    concatBytes(
      new TextEncoder().encode('ECP-CONVERSATION-v1'),
      cmp < 0 ? localPubBytes : peerPubBytes,
      cmp < 0 ? peerPubBytes : localPubBytes,
    ),
  );

  const session: Session = {
    contactFp,
    version: 1,
    conversationId: encodeBase64URL(convIdHash.slice(0, 16)),
    peerIdentity: contact.bundle,
    DHs: { sk: ekKP.secretKey, pk: ekKP.publicKey },
    RK: hkdfSHA256(
      SK,
      new Uint8Array(32),
      new TextEncoder().encode('ECP-DR-ROOT-v1'),
      32,
    ),
    Ns: 0,
    Nr: 0,
    PN: 0,
    SK,
    state: 'HANDSHAKE_SENT',
  };
  await DB.put('sessions', session);
  return { packet: fullPacket, session };
}

export async function ProcessInit(packetBytes: Uint8Array) {
  const local = await getLocalIdentity();
  const localPubBytes = serializeIdentityPublic(local);
  const { headerBytes } = parseHeader(packetBytes);

  let offset = 12;
  const fixedPayloadLen = 4225 * 2 + 32 + 1568 + 4691;
  if (packetBytes.length < 12 + fixedPayloadLen + 16)
    throw new Error('INIT structural integrity fail');

  const sIdBytes = packetBytes.slice(offset, (offset += 4225));
  const rIdBytes = packetBytes.slice(offset, (offset += 4225));
  const ekPubBytes = packetBytes.slice(offset, (offset += 32));
  const kemCt = packetBytes.slice(offset, (offset += 1568));
  const sig = packetBytes.slice(offset, (offset += 4691));
  const ciphertext = packetBytes.slice(offset);

  if (!constantTimeCompare(rIdBytes, localPubBytes))
    throw new Error('INIT dest misrouted');

  const senderFp = calculateFingerprint(sIdBytes);
  const localFp = await getLocalFingerprint();
  if (senderFp === localFp)
    throw new Error('Self-messaging prohibited: packet sent by local node.');

  const senderId = parseIdentityPublic(sIdBytes);
  const sigInput = concatBytes(
    new TextEncoder().encode('ECP-INIT-v1'),
    sIdBytes,
    rIdBytes,
    ekPubBytes,
    kemCt,
  );
  if (!verifyComposite(sig, sigInput, senderId.ecPk, senderId.dsaPk))
    throw new Error('INIT signature rejected');

  let contact = await DB.get('contacts', senderFp);
  if (!contact) {
    contact = {
      fingerprint: senderFp,
      bundle: encodeBase64URL(sIdBytes),
      name: 'Unknown Peer',
      verified: false,
      archived: false,
      lastReadTimestamp: Date.now(),
    };
    await DB.put('contacts', contact);
  }

  const dh1 = getSharedSecretX25519(local.dhSk, ekPubBytes);
  const kemSS = decapsulateMLKEM1024(kemCt, local.kemSk);

  let SK: Uint8Array;
  try {
    SK = hkdfSHA256(
      concatBytes(new TextEncoder().encode('ECP-INIT-v1'), dh1, kemSS),
      new Uint8Array(32),
      new TextEncoder().encode(''),
      32,
    );
  } finally {
    dh1.fill(0);
    kemSS.fill(0);
  }

  const MK0 = hkdfSHA256(
    SK,
    new Uint8Array(32),
    new TextEncoder().encode('ECP-INIT-MESSAGE-v1'),
    32,
  );
  const aesKeyInit = hkdfSHA256(
    MK0,
    new Uint8Array(32),
    new TextEncoder().encode('ECP-AES256GCM-v1'),
    32,
  );
  const nonceBytes = hmacSHA256(
    MK0,
    new TextEncoder().encode('ECP-INIT-NONCE'),
  );

  let ptextBytes: Uint8Array;
  try {
    ptextBytes = decryptGCM(
      aesKeyInit,
      nonceBytes.slice(0, 12),
      ciphertext,
      concatBytes(headerBytes, packetBytes.slice(12, 12 + fixedPayloadLen)),
    );
  } finally {
    aesKeyInit.fill(0);
    MK0.fill(0);
  }

  const RK0 = hkdfSHA256(
    SK,
    new Uint8Array(32),
    new TextEncoder().encode('ECP-DR-ROOT-v1'),
    32,
  );
  const dhsKP = keygenX25519();
  const dhsPubBytes = dhsKP.publicKey;
  const dh2 = getSharedSecretX25519(dhsKP.secretKey, ekPubBytes);
  const drIkm = hkdfSHA256(
    dh2,
    RK0,
    new TextEncoder().encode('ECP-DR-RK-v1'),
    64,
  );

  const cmp = memcmp(localPubBytes, sIdBytes);
  const convIdHash = sha256(
    concatBytes(
      new TextEncoder().encode('ECP-CONVERSATION-v1'),
      cmp < 0 ? localPubBytes : sIdBytes,
      cmp < 0 ? sIdBytes : localPubBytes,
    ),
  );

  const respKey = hkdfSHA256(
    SK,
    new Uint8Array(32),
    new TextEncoder().encode('ECP-RESP-v1'),
    32,
  );
  const respNonce = hmacSHA256(
    SK,
    new TextEncoder().encode('ECP-RESP-NONCE-v1'),
  );
  const respHdr = buildHeader(Config.PACKET_TYPES.RESP, 48);

  let respCt: Uint8Array;
  try {
    respCt = encryptGCM(respKey, respNonce.slice(0, 12), dhsPubBytes, respHdr);
  } finally {
    respKey.fill(0);
  }

  const respPacket = concatBytes(respHdr, respCt);
  const session: Session = {
    contactFp: senderFp,
    version: 1,
    conversationId: encodeBase64URL(convIdHash.slice(0, 16)),
    peerIdentity: contact.bundle,
    DHs: { sk: dhsKP.secretKey, pk: dhsPubBytes },
    DHr: { pk: ekPubBytes },
    RK: drIkm.slice(0, 32),
    CKs: drIkm.slice(32, 64),
    Ns: 0,
    Nr: 0,
    PN: 0,
    state: 'ESTABLISHED',
    lastRespPacket: encodeBase64URL(respPacket),
  };
  drIkm.fill(0);
  await DB.put('sessions', session);
  return {
    session,
    plaintext: new TextDecoder().decode(ptextBytes),
    respPacket,
  };
}

export async function ProcessResp(packetBytes: Uint8Array) {
  if (packetBytes.length < 60) throw new Error('RESP packet truncated');

  const { type, headerBytes } = parseHeader(packetBytes);
  if (type !== Config.PACKET_TYPES.RESP)
    throw new Error('Protocol type mismatch');

  const sessions = await DB.getAll('sessions');
  const candidateSessions = sessions.filter(
    (s) => s.state === 'HANDSHAKE_SENT' && s.SK,
  );

  let targetSession: Session | undefined;
  let rPubBytes: Uint8Array | undefined;

  for (const session of candidateSessions) {
    if (!session.SK) continue;
    const rKey = hkdfSHA256(
      session.SK,
      new Uint8Array(32),
      new TextEncoder().encode('ECP-RESP-v1'),
      32,
    );
    const rNonce = hmacSHA256(
      session.SK,
      new TextEncoder().encode('ECP-RESP-NONCE-v1'),
    );

    try {
      rPubBytes = decryptGCM(
        rKey,
        rNonce.slice(0, 12),
        packetBytes.slice(12),
        headerBytes,
      );
      targetSession = session;
      break;
    } catch {
      // Continue testing remaining candidate sessions if tag check fails
    } finally {
      rKey.fill(0);
    }
  }

  if (!targetSession || !rPubBytes) {
    const isEstablished = sessions.some((s) => s.state === 'ESTABLISHED');
    if (isEstablished)
      return { alreadyEstablished: true, session: sessions[0] };
    throw new Error('Unmatched RESP authentication tag or state error');
  }

  const session = targetSession;
  const dh2 = getSharedSecretX25519(session.DHs.sk, rPubBytes);
  const drIkm = hkdfSHA256(
    dh2,
    session.RK,
    new TextEncoder().encode('ECP-DR-RK-v1'),
    64,
  );

  const oldRK = session.RK;
  session.RK = drIkm.slice(0, 32);
  session.CKr = drIkm.slice(32, 64);
  delete session.CKs;
  session.DHr = { pk: rPubBytes };
  session.state = 'ESTABLISHED';

  const oldSK = session.SK;
  delete session.SK;
  if (oldSK) oldSK.fill(0);
  oldRK.fill(0);
  drIkm.fill(0);

  await DB.put('sessions', session);
  return { alreadyEstablished: false, session };
}

function stepDH(s: Session, rPubBytes?: Uint8Array) {
  if (rPubBytes) {
    const dh = getSharedSecretX25519(s.DHs.sk, rPubBytes);
    let drIkm: Uint8Array;
    try {
      drIkm = hkdfSHA256(
        dh,
        s.RK,
        new TextEncoder().encode('ECP-DR-RK-v1'),
        64,
      );
    } finally {
      dh.fill(0);
    }
    const oldRK = s.RK;
    s.RK = drIkm.slice(0, 32);
    s.CKr = drIkm.slice(32, 64);
    s.DHr = { pk: rPubBytes };
    oldRK.fill(0);
    drIkm.fill(0);
  }
  const nkp = keygenX25519();
  if (!s.DHr) throw new Error('Cannot step DH: Remote DH key (DHr) is missing');

  const dh2 = getSharedSecretX25519(nkp.secretKey, s.DHr.pk);
  let drIkm2: Uint8Array;
  try {
    drIkm2 = hkdfSHA256(
      dh2,
      s.RK,
      new TextEncoder().encode('ECP-DR-RK-v1'),
      64,
    );
  } finally {
    dh2.fill(0);
  }
  const oldRK2 = s.RK;
  s.RK = drIkm2.slice(0, 32);
  s.CKs = drIkm2.slice(32, 64);

  const oldDHsSk = s.DHs.sk;
  s.DHs = { sk: nkp.secretKey, pk: nkp.publicKey };
  oldDHsSk.fill(0);
  oldRK2.fill(0);
  drIkm2.fill(0);
}

export async function EncryptMessage(session: Session, plaintextStr: string) {
  if (session.state !== 'ESTABLISHED')
    throw new Error('Channel constraint violation');
  if (!session.CKs) stepDH(session);
  if (!session.CKs) throw new Error('Failed to derive sending chain key (CKs)');

  const sendingCK = session.CKs;
  const MK = hmacSHA256(sendingCK, new Uint8Array([0x01]));
  const CK_next = hmacSHA256(sendingCK, new Uint8Array([0x02]));
  const aesKey = hkdfSHA256(
    MK,
    new Uint8Array(32),
    new TextEncoder().encode('ECP-AES256GCM-v1'),
    32,
  );
  const nonce = hmacSHA256(MK, new TextEncoder().encode('ECP-NONCE-v1'));

  const cIdBytes = decodeBase64URL(session.conversationId);
  const lPubBytes = serializeIdentityPublic(await getLocalIdentity());
  const headerVals = new Uint8Array(8);
  const dv = new DataView(headerVals.buffer);
  dv.setUint32(0, session.PN);
  dv.setUint32(4, session.Ns);

  const msgHdr = concatBytes(cIdBytes, session.DHs.pk, headerVals);
  const aad = concatBytes(
    new TextEncoder().encode('ECP-MSG-v1'),
    cIdBytes,
    lPubBytes,
    decodeBase64URL(session.peerIdentity),
    msgHdr,
  );

  let ct: Uint8Array;
  try {
    ct = encryptGCM(
      aesKey,
      nonce.slice(0, 12),
      new TextEncoder().encode(plaintextStr),
      aad,
    );
  } finally {
    aesKey.fill(0);
    MK.fill(0);
  }

  const payload = concatBytes(msgHdr, ct);
  const oldCKs = session.CKs;
  session.CKs = CK_next;
  session.Ns++;
  oldCKs.fill(0);

  // DO NOT delete lastRespPacket here, as it may be needed for retransmission
  // delete session.lastRespPacket;
  await DB.put('sessions', session);

  return concatBytes(
    buildHeader(Config.PACKET_TYPES.MSG, payload.length),
    payload,
  );
}

export async function DecryptMessage(packetBytes: Uint8Array) {
  if (packetBytes.length < 84) throw new Error('MSG packet truncated');

  const { type } = parseHeader(packetBytes);
  if (type !== Config.PACKET_TYPES.MSG)
    throw new Error('Protocol type mismatch');

  let offset = 12;
  const cIdBytes = packetBytes.slice(offset, (offset += 16));
  const dhPubBytes = packetBytes.slice(offset, (offset += 32));
  const dv = new DataView(
    packetBytes.buffer,
    packetBytes.byteOffset,
    packetBytes.byteLength,
  );

  const pn = dv.getUint32(offset);
  offset += 4;
  const n = dv.getUint32(offset);
  offset += 4;

  const session = await DB.getByIndex(
    'sessions',
    'conversationId',
    encodeBase64URL(cIdBytes),
  );
  if (!session || !session.DHr) throw new Error('Orphaned payload');

  const aad = concatBytes(
    new TextEncoder().encode('ECP-MSG-v1'),
    cIdBytes,
    decodeBase64URL(session.peerIdentity),
    serializeIdentityPublic(await getLocalIdentity()),
    packetBytes.slice(12, 12 + 56),
  );

  session.skippedKeys ??= {};
  const dhKeyTag = encodeBase64URL(dhPubBytes);
  const cacheKey = `${dhKeyTag}_${n}`;

  if (session.skippedKeys[cacheKey]) {
    const mk = decodeBase64URL(session.skippedKeys[cacheKey]);
    delete session.skippedKeys[cacheKey];
    const aesKey = hkdfSHA256(
      mk,
      new Uint8Array(32),
      new TextEncoder().encode('ECP-AES256GCM-v1'),
      32,
    );
    const nonce = hmacSHA256(mk, new TextEncoder().encode('ECP-NONCE-v1'));

    let ptext: Uint8Array;
    try {
      ptext = decryptGCM(
        aesKey,
        nonce.slice(0, 12),
        packetBytes.slice(offset),
        aad,
      );
    } finally {
      aesKey.fill(0);
      mk.fill(0);
    }
    await DB.put('sessions', session);
    return { session, plaintext: new TextDecoder().decode(ptext) };
  }

  if (!constantTimeCompare(dhPubBytes, session.DHr.pk)) {
    if (session.CKr) {
      while (session.Nr < pn) {
        const skippedMK = hmacSHA256(session.CKr, new Uint8Array([0x01]));
        const oldDhTag = encodeBase64URL(session.DHr.pk);
        session.skippedKeys[`${oldDhTag}_${session.Nr}`] =
          encodeBase64URL(skippedMK);
        skippedMK.fill(0);
        const nextCKr = hmacSHA256(session.CKr, new Uint8Array([0x02]));
        session.CKr.fill(0);
        session.CKr = nextCKr;
        session.Nr++;
      }
    }
    session.PN = session.Ns;
    session.Ns = 0;
    session.Nr = 0;
    stepDH(session, dhPubBytes);
  }

  if (n < session.Nr) throw new Error('Message frame out of order or replayed');
  if (n - session.Nr > 2000) throw new Error('Excessive message gap');

  while (session.Nr < n) {
    if (!session.CKr) throw new Error('CKr fault');
    const skippedMK = hmacSHA256(session.CKr, new Uint8Array([0x01]));
    session.skippedKeys[`${dhKeyTag}_${session.Nr}`] =
      encodeBase64URL(skippedMK);
    skippedMK.fill(0);

    const nextCKr = hmacSHA256(session.CKr, new Uint8Array([0x02]));
    session.CKr.fill(0);
    session.CKr = nextCKr;
    session.Nr++;
  }

  if (!session.CKr) throw new Error('Receiving chain key (CKr) unavailable');
  const receivingCK = session.CKr;

  const MK = hmacSHA256(receivingCK, new Uint8Array([0x01]));
  const CK_next = hmacSHA256(receivingCK, new Uint8Array([0x02]));
  const aesKey = hkdfSHA256(
    MK,
    new Uint8Array(32),
    new TextEncoder().encode('ECP-AES256GCM-v1'),
    32,
  );
  const nonce = hmacSHA256(MK, new TextEncoder().encode('ECP-NONCE-v1'));

  let ptext: Uint8Array;
  try {
    ptext = decryptGCM(
      aesKey,
      nonce.slice(0, 12),
      packetBytes.slice(offset),
      aad,
    );
  } finally {
    aesKey.fill(0);
    MK.fill(0);
  }

  const oldCKr = session.CKr;
  session.CKr = CK_next;
  session.Nr++;
  oldCKr.fill(0);

  delete session.lastRespPacket;
  await DB.put('sessions', session);

  return { session, plaintext: new TextDecoder().decode(ptext) };
}
