import { Config } from './config.js';
import {
  concatBytes,
  keygenEd25519,
  keygenMLDSA87,
  keygenX25519,
  keygenMLKEM1024,
  sha256,
  encodeBase64URL,
} from './crypto.js';
import { DB } from './storage.js';
import type { Identity } from './types.js';

export const getLocalIdentity = async () => {
  let id = await DB.get('identity', 'local');

  if (!id) {
    const ecKP = keygenEd25519();
    const dsaKP = keygenMLDSA87();
    const dhKP = keygenX25519();
    const kemKP = keygenMLKEM1024();

    id = {
      id: 'local',
      ecSk: ecKP.secretKey,
      ecPk: ecKP.publicKey,
      dsaSk: dsaKP.secretKey,
      dsaPk: dsaKP.publicKey,
      dhSk: dhKP.secretKey,
      dhPk: dhKP.publicKey,
      kemSk: kemKP.secretKey,
      kemPk: kemKP.publicKey,
    };
    await DB.put('identity', id);
  }
  return id;
};

export const serializeIdentityPublic = (id: Identity) =>
  concatBytes(
    new Uint8Array([Config.IDENTITY_VERSION]),
    id.ecPk,
    id.dsaPk,
    id.dhPk,
    id.kemPk,
  );

export const parseIdentityPublic = (bytes: Uint8Array) => {
  if (bytes.length < 4225) throw new Error('Identity packet malformed');
  if (bytes[0] !== Config.IDENTITY_VERSION)
    throw new Error('Unsupported identity version');
  return {
    ecPk: bytes.slice(1, 33),
    dsaPk: bytes.slice(33, 2625),
    dhPk: bytes.slice(2625, 2657),
    kemPk: bytes.slice(2657, 4225),
  };
};

export const calculateFingerprint = (identityBytes: Uint8Array) => {
  const idPub = parseIdentityPublic(identityBytes);
  return encodeBase64URL(
    sha256(
      concatBytes(
        new TextEncoder().encode('ECP-ID-v1'),
        idPub.ecPk,
        idPub.dsaPk,
        idPub.dhPk,
        idPub.kemPk,
      ),
    ),
  );
};

export const getLocalFingerprint = async () =>
  calculateFingerprint(serializeIdentityPublic(await getLocalIdentity()));
