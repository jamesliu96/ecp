import { buildHeader, parseHeader } from './codec.js';
import { Config } from './config.js';
import { encodeBase64URL, decodeBase64URL, concatBytes, sha256, hkdfSHA256, hmacSHA256, encryptGCM, decryptGCM, encapsulateMLKEM1024, decapsulateMLKEM1024, keygenX25519, getSharedSecretX25519, keygenMLKEM1024, signComposite, verifyComposite, constantTimeCompare, } from './crypto.js';
import { getLocalFingerprint, getLocalIdentity, serializeIdentityPublic, parseIdentityPublic, calculateFingerprint, } from './identity.js';
import { DB } from './storage.js';
const utf8 = (s) => new TextEncoder().encode(s);
const ZEROS = new Uint8Array(32);
const deriveSymmetric = (mk, keyLabel, nonceLabel) => ({
    key: hkdfSHA256(mk, ZEROS, utf8(keyLabel), 32),
    nonce: hmacSHA256(mk, utf8(nonceLabel)).slice(0, 12),
});
const kdfRoot = (rk, dh, kem) => hkdfSHA256(concatBytes(dh, kem), rk, utf8('ECP-DR-RK-v1'), 64);
const deriveInitKeys = (sk) => {
    const mk = hkdfSHA256(sk, ZEROS, utf8('ECP-INIT-MESSAGE-v1'), 32);
    return deriveSymmetric(mk, 'ECP-AES256GCM-v1', 'ECP-INIT-NONCE');
};
const deriveMsgKeys = (ck) => {
    const mk = hmacSHA256(ck, new Uint8Array([0x01]));
    const nextCk = hmacSHA256(ck, new Uint8Array([0x02]));
    return {
        ...deriveSymmetric(mk, 'ECP-AES256GCM-v1', 'ECP-NONCE-v1'),
        nextCk,
        mk,
    };
};
export async function CreateInit(contactFp, plaintextStr) {
    const localFp = await getLocalFingerprint();
    if (contactFp === localFp)
        throw new Error('Self-messaging is prohibited.');
    const local = await getLocalIdentity();
    const contact = await DB.get('contacts', contactFp);
    if (!contact)
        throw new Error('Peer context is missing.');
    const localPubBytes = serializeIdentityPublic(local);
    const peerPubBytes = decodeBase64URL(contact.bundle);
    const peerId = parseIdentityPublic(peerPubBytes);
    const ekKP = keygenX25519();
    const kemRes = encapsulateMLKEM1024(peerId.kemPk);
    const dh1 = getSharedSecretX25519(ekKP.secretKey, peerId.dhPk);
    const SK = hkdfSHA256(concatBytes(utf8('ECP-INIT-v1'), dh1, kemRes.sharedSecret), ZEROS, utf8(''), 32);
    const sigInput = concatBytes(utf8('ECP-INIT-v1'), localPubBytes, peerPubBytes, ekKP.publicKey, kemRes.cipherText);
    const sig = signComposite(sigInput, local.ecSk, local.dsaSk);
    const initCrypto = deriveInitKeys(SK);
    const payloadFixed = concatBytes(localPubBytes, peerPubBytes, ekKP.publicKey, kemRes.cipherText, sig);
    const ptextEnc = utf8(plaintextStr);
    const header = buildHeader(Config.PACKET_TYPES.INIT, payloadFixed.length + ptextEnc.length + 16);
    const aad = concatBytes(header, payloadFixed);
    const ciphertext = encryptGCM(initCrypto.key, initCrypto.nonce, ptextEnc, aad);
    const fullPacket = concatBytes(header, payloadFixed, ciphertext);
    const convIdHash = sha256(concatBytes(utf8('ECP-CONVERSATION-v1'), ekKP.publicKey, kemRes.cipherText));
    const session = {
        contactFp,
        version: 1,
        conversationId: encodeBase64URL(convIdHash.slice(0, 16)),
        peerIdentity: contact.bundle,
        DHs: { sk: ekKP.secretKey, pk: ekKP.publicKey },
        KEMs: { sk: local.kemSk, pk: local.kemPk },
        KEMr: { pk: peerId.kemPk },
        RK: hkdfSHA256(SK, ZEROS, utf8('ECP-DR-ROOT-v1'), 32),
        Ns: 0,
        Nr: 0,
        PN: 0,
        SK,
        state: 'HANDSHAKE_SENT',
    };
    await DB.put('sessions', session);
    return { packet: fullPacket, session };
}
export async function ProcessInit(packetBytes) {
    const local = await getLocalIdentity();
    const localPubBytes = serializeIdentityPublic(local);
    const { headerBytes } = parseHeader(packetBytes);
    let offset = 12;
    const fixedPayloadLen = 4225 * 2 + 32 + 1568 + 4691;
    if (packetBytes.length < 12 + fixedPayloadLen + 16)
        throw new Error('INIT packet structural integrity check failed.');
    const sIdBytes = packetBytes.slice(offset, (offset += 4225));
    const rIdBytes = packetBytes.slice(offset, (offset += 4225));
    const ekPubBytes = packetBytes.slice(offset, (offset += 32));
    const kemCt = packetBytes.slice(offset, (offset += 1568));
    const sig = packetBytes.slice(offset, (offset += 4691));
    const ciphertext = packetBytes.slice(offset);
    if (!constantTimeCompare(rIdBytes, localPubBytes))
        throw new Error('INIT packet destination misrouted.');
    const senderFp = calculateFingerprint(sIdBytes);
    if (senderFp === (await getLocalFingerprint()))
        throw new Error('Self-messaging is prohibited.');
    const sigHash = encodeBase64URL(sha256(sig));
    const existingSession = await DB.get('sessions', senderFp);
    if (existingSession?.usedInitEks?.includes(sigHash))
        throw new Error('INIT packet replay detected.');
    const senderId = parseIdentityPublic(sIdBytes);
    const sigInput = concatBytes(utf8('ECP-INIT-v1'), sIdBytes, rIdBytes, ekPubBytes, kemCt);
    if (!verifyComposite(sig, sigInput, senderId.ecPk, senderId.dsaPk))
        throw new Error('INIT packet signature verification failed.');
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
    const SK = hkdfSHA256(concatBytes(utf8('ECP-INIT-v1'), dh1, kemSS), ZEROS, utf8(''), 32);
    const initCrypto = deriveInitKeys(SK);
    const ptextBytes = decryptGCM(initCrypto.key, initCrypto.nonce, ciphertext, concatBytes(headerBytes, packetBytes.slice(12, 12 + fixedPayloadLen)));
    const RK0 = hkdfSHA256(SK, ZEROS, utf8('ECP-DR-ROOT-v1'), 32);
    const dhsKP = keygenX25519();
    const nkemKP = keygenMLKEM1024();
    const dh2 = getSharedSecretX25519(dhsKP.secretKey, ekPubBytes);
    const kemRes2 = encapsulateMLKEM1024(senderId.kemPk);
    const drIkm = kdfRoot(RK0, dh2, kemRes2.sharedSecret);
    const convIdHash = sha256(concatBytes(utf8('ECP-CONVERSATION-v1'), ekPubBytes, kemCt));
    const respCrypto = deriveSymmetric(SK, 'ECP-RESP-v1', 'ECP-RESP-NONCE-v1');
    const respPayload = concatBytes(dhsKP.publicKey, kemRes2.cipherText, nkemKP.publicKey);
    const respHdr = buildHeader(Config.PACKET_TYPES.RESP, respPayload.length + 16);
    const respCt = encryptGCM(respCrypto.key, respCrypto.nonce, respPayload, respHdr);
    const respPacket = concatBytes(respHdr, respCt);
    const session = {
        contactFp: senderFp,
        version: 1,
        conversationId: encodeBase64URL(convIdHash.slice(0, 16)),
        peerIdentity: contact.bundle,
        DHs: { sk: dhsKP.secretKey, pk: dhsKP.publicKey },
        DHr: { pk: ekPubBytes },
        KEMs: { sk: nkemKP.secretKey, pk: nkemKP.publicKey },
        KEMr: { pk: senderId.kemPk },
        pendingKemCt: kemRes2.cipherText,
        RK: drIkm.slice(0, 32),
        CKs: drIkm.slice(32, 64),
        Ns: 0,
        Nr: 0,
        PN: 0,
        state: 'ESTABLISHED',
        lastRespPacket: encodeBase64URL(respPacket),
        usedInitEks: [...(existingSession?.usedInitEks ?? []), sigHash].slice(-100),
    };
    await DB.put('sessions', session);
    return {
        session,
        plaintext: new TextDecoder().decode(ptextBytes),
        respPacket,
    };
}
export async function ProcessResp(packetBytes) {
    if (packetBytes.length < 3196)
        throw new Error('RESP packet is truncated.');
    const { type, headerBytes } = parseHeader(packetBytes);
    if (type !== Config.PACKET_TYPES.RESP)
        throw new Error('Protocol type mismatch.');
    const sessions = await DB.getAll('sessions');
    const candidateSessions = sessions
        .filter((s) => s.state === 'HANDSHAKE_SENT' && s.SK)
        .slice(-10);
    let targetSession;
    let respPlaintext;
    for (const session of candidateSessions) {
        if (!session.SK)
            continue;
        const { key, nonce } = deriveSymmetric(session.SK, 'ECP-RESP-v1', 'ECP-RESP-NONCE-v1');
        try {
            respPlaintext = decryptGCM(key, nonce, packetBytes.slice(12), headerBytes);
            targetSession = session;
            break;
        }
        catch { }
    }
    if (!targetSession || !respPlaintext) {
        if (sessions.some((s) => s.state === 'ESTABLISHED'))
            return { alreadyEstablished: true, session: sessions[0] };
        throw new Error('RESP packet processing failed.');
    }
    const dhsPubBytes = respPlaintext.slice(0, 32);
    const kemCt = respPlaintext.slice(32, 1600);
    const kemPubBytes = respPlaintext.slice(1600, 3168);
    const local = await getLocalIdentity();
    const dh2 = getSharedSecretX25519(targetSession.DHs.sk, dhsPubBytes);
    const kemSS2 = decapsulateMLKEM1024(kemCt, local.kemSk);
    const drIkm = kdfRoot(targetSession.RK, dh2, kemSS2);
    targetSession.RK = drIkm.slice(0, 32);
    targetSession.CKr = drIkm.slice(32, 64);
    delete targetSession.CKs;
    targetSession.DHr = { pk: dhsPubBytes };
    targetSession.KEMs = { sk: local.kemSk, pk: local.kemPk };
    targetSession.KEMr = { pk: kemPubBytes };
    targetSession.state = 'ESTABLISHED';
    delete targetSession.SK;
    await DB.put('sessions', targetSession);
    return { alreadyEstablished: false, session: targetSession };
}
function stepDH(s) {
    if (!s.DHr || !s.KEMr)
        throw new Error('Cannot advance DH ratchet: remote keys are missing.');
    const nkp = keygenX25519();
    const nkem = keygenMLKEM1024();
    const kemRes = encapsulateMLKEM1024(s.KEMr.pk);
    const dh2 = getSharedSecretX25519(nkp.secretKey, s.DHr.pk);
    const drIkm = kdfRoot(s.RK, dh2, kemRes.sharedSecret);
    s.RK = drIkm.slice(0, 32);
    s.CKs = drIkm.slice(32, 64);
    s.DHs = { sk: nkp.secretKey, pk: nkp.publicKey };
    s.KEMs = { sk: nkem.secretKey, pk: nkem.publicKey };
    s.pendingKemCt = kemRes.cipherText;
}
export async function EncryptMessage(session, plaintextStr) {
    if (session.state !== 'ESTABLISHED')
        throw new Error('Channel state constraint violation.');
    if (!session.CKs)
        stepDH(session);
    if (!session.CKs || !session.pendingKemCt || !session.KEMs)
        throw new Error('Missing sending chain (CKs).');
    const { key, nonce, nextCk } = deriveMsgKeys(session.CKs);
    const cIdBytes = decodeBase64URL(session.conversationId);
    const lPubBytes = serializeIdentityPublic(await getLocalIdentity());
    const headerVals = new Uint8Array(8);
    const dv = new DataView(headerVals.buffer);
    dv.setUint32(0, session.PN);
    dv.setUint32(4, session.Ns);
    const msgHdr = concatBytes(cIdBytes, session.DHs.pk, session.pendingKemCt, session.KEMs.pk, headerVals);
    const aad = concatBytes(utf8('ECP-MSG-v1'), cIdBytes, lPubBytes, decodeBase64URL(session.peerIdentity), msgHdr);
    const ct = encryptGCM(key, nonce, utf8(plaintextStr), aad);
    const payload = concatBytes(msgHdr, ct);
    session.CKs = nextCk;
    session.Ns++;
    await DB.put('sessions', session);
    return concatBytes(buildHeader(Config.PACKET_TYPES.MSG, payload.length), payload);
}
export async function DecryptMessage(packetBytes) {
    if (packetBytes.length < 3220)
        throw new Error('Invalid message packet.');
    const { type } = parseHeader(packetBytes);
    if (type !== Config.PACKET_TYPES.MSG)
        throw new Error('Invalid message packet type.');
    let offset = 12;
    const cIdBytes = packetBytes.slice(offset, (offset += 16));
    const dhPubBytes = packetBytes.slice(offset, (offset += 32));
    const kemCt = packetBytes.slice(offset, (offset += 1568));
    const kemPubBytes = packetBytes.slice(offset, (offset += 1568));
    const dv = new DataView(packetBytes.buffer, packetBytes.byteOffset, packetBytes.byteLength);
    const pn = dv.getUint32(offset);
    offset += 4;
    const n = dv.getUint32(offset);
    offset += 4;
    const session = await DB.getByIndex('sessions', 'conversationId', encodeBase64URL(cIdBytes));
    if (!session || !session.DHr)
        throw new Error('Message decryption failed.');
    const aad = concatBytes(utf8('ECP-MSG-v1'), cIdBytes, decodeBase64URL(session.peerIdentity), serializeIdentityPublic(await getLocalIdentity()), packetBytes.slice(12, 12 + 3192));
    session.skippedKeys ??= {};
    const dhKeyTag = encodeBase64URL(dhPubBytes);
    const cacheKey = `${dhKeyTag}_${n}`;
    if (session.skippedKeys[cacheKey]) {
        const { key, nonce } = deriveSymmetric(decodeBase64URL(session.skippedKeys[cacheKey]), 'ECP-AES256GCM-v1', 'ECP-NONCE-v1');
        try {
            const ptext = decryptGCM(key, nonce, packetBytes.slice(offset), aad);
            delete session.skippedKeys[cacheKey];
            await DB.put('sessions', session);
            return { session, plaintext: new TextDecoder().decode(ptext) };
        }
        catch {
            throw new Error('Message decryption failed.');
        }
    }
    let tempCKr = session.CKr;
    let tempRK = session.RK;
    let tempPN = session.PN, tempNs = session.Ns, tempNr = session.Nr;
    let stepped = false;
    const stage = { ...session };
    const newSkippedKeys = {};
    if (!constantTimeCompare(dhPubBytes, session.DHr.pk)) {
        stepped = true;
        if (tempCKr)
            while (tempNr < pn) {
                const { mk, nextCk } = deriveMsgKeys(tempCKr);
                newSkippedKeys[`${encodeBase64URL(session.DHr.pk)}_${tempNr}`] =
                    encodeBase64URL(mk);
                tempCKr = nextCk;
                tempNr++;
            }
        tempPN = tempNs;
        tempNs = 0;
        tempNr = 0;
        if (!stage.KEMs)
            throw new Error('Message decryption failed.');
        const dh1 = getSharedSecretX25519(stage.DHs.sk, dhPubBytes);
        const kemSS = decapsulateMLKEM1024(kemCt, stage.KEMs.sk);
        const drIkm1 = kdfRoot(tempRK, dh1, kemSS);
        tempRK = drIkm1.slice(0, 32);
        tempCKr = drIkm1.slice(32, 64);
        stage.DHr = { pk: dhPubBytes };
        stage.KEMr = { pk: kemPubBytes };
        const nkp = keygenX25519();
        const nkem = keygenMLKEM1024();
        const kemRes = encapsulateMLKEM1024(stage.KEMr.pk);
        const dh2 = getSharedSecretX25519(nkp.secretKey, stage.DHr.pk);
        const drIkm2 = kdfRoot(tempRK, dh2, kemRes.sharedSecret);
        tempRK = drIkm2.slice(0, 32);
        stage.CKs = drIkm2.slice(32, 64);
        stage.DHs = { sk: nkp.secretKey, pk: nkp.publicKey };
        stage.KEMs = { sk: nkem.secretKey, pk: nkem.publicKey };
        stage.pendingKemCt = kemRes.cipherText;
    }
    if (n < tempNr || n - tempNr > 2000)
        throw new Error('Message decryption failed.');
    while (tempNr < n) {
        if (!tempCKr)
            throw new Error('Message decryption failed.');
        const { mk, nextCk } = deriveMsgKeys(tempCKr);
        newSkippedKeys[`${dhKeyTag}_${tempNr}`] = encodeBase64URL(mk);
        tempCKr = nextCk;
        tempNr++;
    }
    if (!tempCKr)
        throw new Error('Message decryption failed.');
    const { key, nonce, nextCk } = deriveMsgKeys(tempCKr);
    let ptext;
    try {
        ptext = decryptGCM(key, nonce, packetBytes.slice(offset), aad);
    }
    catch {
        throw new Error('Message decryption failed.');
    }
    session.CKr = nextCk;
    if (stepped)
        Object.assign(session, stage, { RK: tempRK });
    session.PN = tempPN;
    session.Ns = tempNs;
    session.Nr = tempNr + 1;
    session.skippedKeys = { ...session.skippedKeys, ...newSkippedKeys };
    const ks = Object.keys(session.skippedKeys);
    if (ks.length > 100)
        for (const k of ks.slice(0, ks.length - 100))
            delete session.skippedKeys[k];
    delete session.lastRespPacket;
    await DB.put('sessions', session);
    return { session, plaintext: new TextDecoder().decode(ptext) };
}
//# sourceMappingURL=ratchet.js.map