import { Config } from './config.js';
import { concatBytes, keygenMLDSA87, keygenMLKEM1024, keygenX25519, sha256, encodeBase64URL, } from './crypto.js';
import { DB } from './storage.js';
export const getLocalIdentity = async () => {
    let id = await DB.get('identity', 'local');
    if (!id) {
        const dsaKP = await keygenMLDSA87();
        const dhKP = await keygenX25519();
        const pqKP = await keygenMLKEM1024();
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
export const serializeIdentityPublic = (id) => concatBytes(new Uint8Array([Config.IDENTITY_VERSION]), id.dsaPk, id.dhPk, id.kemPk);
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
export const calculateFingerprint = async (identityBytes) => {
    const idPub = parseIdentityPublic(identityBytes);
    return encodeBase64URL(await sha256(concatBytes(new TextEncoder().encode('ECP-ID-v1'), idPub.dsaPk, idPub.dhPk, idPub.kemPk)));
};
export const getLocalFingerprint = async () => await calculateFingerprint(serializeIdentityPublic(await getLocalIdentity()));
//# sourceMappingURL=identity.js.map