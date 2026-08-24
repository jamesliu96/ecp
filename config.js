export const Config = {
    WIRE_PROTOCOL_VERSION: 0x01,
    IDENTITY_VERSION: 0x01,
    STORAGE_DB_NAME: 'ECP_DB',
    STORAGE_DB_VERSION: 1,
    PACKET_MAGIC: new Uint8Array([0x45, 0x32, 0x45, 0x31]),
    PACKET_TYPES: { INIT: 0x01, RESP: 0x02, MSG: 0x03 },
    MAX_PACKET_SIZE: 5 * 1024 * 1024,
    PREFIX: 'e2e1:',
};
//# sourceMappingURL=config.js.map