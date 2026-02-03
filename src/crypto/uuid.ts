/**
 * UUIDv7 Generator
 * RFC 9562 compliant - timestamp-ordered for causality
 * No external dependencies
 * @module crypto/uuid
 */

/**
 * Generate cryptographically random bytes
 * Works in both Node.js and browser environments
 */
function getRandomBytes(count: number): Uint8Array {
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        // Browser or Node.js with webcrypto
        const bytes = new Uint8Array(count);
        crypto.getRandomValues(bytes);
        return bytes;
    }

    // Fallback for environments without crypto
    // This should not happen in modern runtimes
    const bytes = new Uint8Array(count);
    for (let i = 0; i < count; i++) {
        bytes[i] = Math.floor(Math.random() * 256);
    }
    return bytes;
}

/**
 * Generate a UUIDv7 string
 * Format: xxxxxxxx-xxxx-7xxx-yxxx-xxxxxxxxxxxx
 * Where first 48 bits are Unix timestamp in milliseconds
 * 
 * @returns UUIDv7 string in standard format
 */
export function generateUUIDv7(): string {
    const timestamp = Date.now();
    const random = getRandomBytes(10);

    // Build the 16-byte UUID
    const uuid = new Uint8Array(16);

    // Bytes 0-5: 48-bit timestamp (big-endian)
    uuid[0] = (timestamp / 0x10000000000) & 0xff;
    uuid[1] = (timestamp / 0x100000000) & 0xff;
    uuid[2] = (timestamp / 0x1000000) & 0xff;
    uuid[3] = (timestamp / 0x10000) & 0xff;
    uuid[4] = (timestamp / 0x100) & 0xff;
    uuid[5] = timestamp & 0xff;

    // Bytes 6-7: version (7) and random
    uuid[6] = 0x70 | ((random[0] ?? 0) & 0x0f); // Version 7
    uuid[7] = random[1] ?? 0;

    // Byte 8: variant (10xx) and random
    uuid[8] = 0x80 | ((random[2] ?? 0) & 0x3f); // Variant 10

    // Bytes 9-15: random
    uuid[9] = random[3] ?? 0;
    uuid[10] = random[4] ?? 0;
    uuid[11] = random[5] ?? 0;
    uuid[12] = random[6] ?? 0;
    uuid[13] = random[7] ?? 0;
    uuid[14] = random[8] ?? 0;
    uuid[15] = random[9] ?? 0;

    // Convert to hex string with dashes
    const hex = Array.from(uuid)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

/**
 * Extract timestamp from UUIDv7
 * @param uuid - UUIDv7 string
 * @returns Unix timestamp in milliseconds
 */
export function extractTimestamp(uuid: string): number {
    const hex = uuid.replace(/-/g, '');
    const timestampHex = hex.slice(0, 12);
    return parseInt(timestampHex, 16);
}

/**
 * Validate UUIDv7 format
 * @param uuid - String to validate
 * @returns True if valid UUIDv7 format
 */
export function isValidUUIDv7(uuid: string): boolean {
    const pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return pattern.test(uuid);
}

/**
 * Compare two UUIDv7 values for temporal ordering
 * @param a - First UUIDv7
 * @param b - Second UUIDv7
 * @returns -1 if a < b, 0 if equal, 1 if a > b
 */
export function compareUUIDv7(a: string, b: string): -1 | 0 | 1 {
    const hexA = a.replace(/-/g, '').toLowerCase();
    const hexB = b.replace(/-/g, '').toLowerCase();

    if (hexA < hexB) return -1;
    if (hexA > hexB) return 1;
    return 0;
}
