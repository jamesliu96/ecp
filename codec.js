import { Config } from './config.js';
import { decodeBase64URL, encodeBase64URL } from './crypto.js';
export const buildHeader = (type, payloadLength) => {
    const hdr = new Uint8Array(12);
    hdr.set(Config.PACKET_MAGIC, 0);
    hdr[4] = Config.WIRE_PROTOCOL_VERSION;
    hdr[5] = type;
    new DataView(hdr.buffer).setUint32(8, payloadLength);
    return hdr;
};
export const parseHeader = (bytes) => {
    if (bytes.length < 12)
        throw new Error('Packet length violation');
    for (let i = 0; i < 4; i++)
        if (bytes[i] !== Config.PACKET_MAGIC[i])
            throw new Error('Magic mismatch');
    if (bytes[4] !== Config.WIRE_PROTOCOL_VERSION)
        throw new Error('Unsupported wire version');
    return {
        type: bytes[5],
        payloadLength: new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(8),
        headerBytes: bytes.slice(0, 12),
    };
};
export const formatEnvelope = (bytes) => `${Config.PREFIX}${encodeBase64URL(bytes)}`;
export const parseEnvelope = (str) => {
    const trimmed = str.trim();
    if (!trimmed.startsWith(Config.PREFIX))
        throw new Error('Not a valid ECP envelope');
    return decodeBase64URL(trimmed.substring(Config.PREFIX.length).trim());
};
//# sourceMappingURL=codec.js.map