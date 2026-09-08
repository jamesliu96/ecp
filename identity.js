import { Config } from './config.js';
import { concatBytes, keygenMLDSA87, keygenMLKEM1024, keygenX25519, sha256, encodeBase64URL, } from './crypto.js';
import { DB } from './storage.js';
export const getLocalIdentity = async () => {
    let id = await DB.get('identity', 'local');
    if (!id) {
        const dsaKP = keygenMLDSA87();
        const dhKP = keygenX25519();
        const pqKP = keygenMLKEM1024();
        id = {
            id: 'local',
            dsaSk: dsaKP.secretKey,
            dsaPk: dsaKP.publicKey,
            dhSk: dhKP.secretKey,
            dhPk: dhKP.publicKey,
            kemSk: pqKP.secretKey,
            kemPk: pqKP.publicKey,
        };
        await DB.put('identity', id);
    }
    return id;
};
export const serializeIdentityPublic = (id) => concatBytes(new Uint8Array([Config.IDENTITY_VERSION]), id.dsaPk.slice(0, 2592), id.dhPk.slice(0, 32), id.kemPk.slice(0, 1568));
export const parseIdentityPublic = (bytes) => {
    if (bytes.length < 4193)
        throw new Error('Identity packet malformed');
    if (bytes[0] !== Config.IDENTITY_VERSION)
        throw new Error('Unsupported identity version');
    return {
        dsaPk: bytes.slice(1, 2593),
        dhPk: bytes.slice(2593, 2625),
        kemPk: bytes.slice(2625, 4193),
    };
};
export const calculateFingerprint = (identityBytes) => {
    const idPub = parseIdentityPublic(identityBytes);
    return encodeBase64URL(sha256(concatBytes(new TextEncoder().encode('ECP-ID-v1'), idPub.dsaPk, idPub.dhPk, idPub.kemPk)));
};
export const getLocalFingerprint = async () => calculateFingerprint(serializeIdentityPublic(await getLocalIdentity()));
//# sourceMappingURL=identity.js.map