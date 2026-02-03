/**
 * Pure JavaScript SHA3-256 (Keccak-256) Implementation
 * NIST FIPS 202 compliant
 * No external dependencies - suitable for browser and Node.js
 * @module crypto/sha3
 */

// Keccak round constants
const RC: bigint[] = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
];

// Rotation offsets
const ROTATIONS: number[] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20,
    3, 10, 43, 25, 39, 41, 45, 15, 21, 8,
    18, 2, 61, 56, 14
];

const MASK64 = 0xffffffffffffffffn;

/**
 * Rotate left for 64-bit bigint
 */
function rotl64(x: bigint, n: number): bigint {
    return ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK64;
}

/**
 * Keccak-f[1600] permutation
 */
function keccakF(state: bigint[]): void {
    const c: bigint[] = [0n, 0n, 0n, 0n, 0n];
    const b: bigint[] = new Array<bigint>(25).fill(0n);

    for (let round = 0; round < 24; round++) {
        // Theta
        for (let x = 0; x < 5; x++) {
            c[x] = (state[x] ?? 0n) ^ (state[x + 5] ?? 0n) ^ (state[x + 10] ?? 0n) ^ (state[x + 15] ?? 0n) ^ (state[x + 20] ?? 0n);
        }

        for (let x = 0; x < 5; x++) {
            const c4 = c[(x + 4) % 5] ?? 0n;
            const c1 = c[(x + 1) % 5] ?? 0n;
            const d = c4 ^ rotl64(c1, 1);
            for (let y = 0; y < 25; y += 5) {
                state[y + x] = ((state[y + x] ?? 0n) ^ d) & MASK64;
            }
        }

        // Rho and Pi
        for (let i = 0; i < 25; i++) {
            const x = i % 5;
            const y = Math.floor(i / 5);
            const newY = (2 * x + 3 * y) % 5;
            b[y + newY * 5] = rotl64(state[i] ?? 0n, ROTATIONS[i] ?? 0);
        }

        // Chi
        for (let y = 0; y < 25; y += 5) {
            for (let x = 0; x < 5; x++) {
                const b0 = b[y + x] ?? 0n;
                const b1 = b[y + (x + 1) % 5] ?? 0n;
                const b2 = b[y + (x + 2) % 5] ?? 0n;
                state[y + x] = (b0 ^ ((~b1) & b2)) & MASK64;
            }
        }

        // Iota
        state[0] = ((state[0] ?? 0n) ^ (RC[round] ?? 0n)) & MASK64;
    }
}

/**
 * Convert bytes to state
 */
function bytesToLanes(bytes: Uint8Array): bigint[] {
    const lanes: bigint[] = new Array<bigint>(25).fill(0n);
    const len = Math.min(bytes.length, 200);

    for (let i = 0; i < len; i++) {
        const lane = Math.floor(i / 8);
        const offset = (i % 8) * 8;
        lanes[lane] = ((lanes[lane] ?? 0n) | (BigInt(bytes[i] ?? 0) << BigInt(offset))) & MASK64;
    }

    return lanes;
}

/**
 * Extract bytes from state
 */
function lanesToBytes(lanes: bigint[], count: number): Uint8Array {
    const bytes = new Uint8Array(count);
    for (let i = 0; i < count; i++) {
        const lane = Math.floor(i / 8);
        const offset = (i % 8) * 8;
        bytes[i] = Number(((lanes[lane] ?? 0n) >> BigInt(offset)) & 0xffn);
    }
    return bytes;
}

/**
 * XOR bytes into state lanes
 */
function xorBytes(lanes: bigint[], bytes: Uint8Array): void {
    const len = Math.min(bytes.length, 136);
    for (let i = 0; i < len; i++) {
        const lane = Math.floor(i / 8);
        const offset = (i % 8) * 8;
        lanes[lane] = ((lanes[lane] ?? 0n) ^ (BigInt(bytes[i] ?? 0) << BigInt(offset))) & MASK64;
    }
}

/**
 * Compute SHA3-256 hash of input
 * @param input - String or Uint8Array to hash
 * @returns Hex-encoded hash string prefixed with 0x
 */
export function sha3(input: string | Uint8Array): string {
    const message = typeof input === 'string'
        ? new TextEncoder().encode(input)
        : input;

    const rate = 136; // bytes (1088 bits for SHA3-256)
    const outputLen = 32; // bytes (256 bits)

    // Initialize state
    const state: bigint[] = new Array<bigint>(25).fill(0n);

    // Absorb
    let offset = 0;
    while (offset + rate <= message.length) {
        const block = message.slice(offset, offset + rate);
        xorBytes(state, block);
        keccakF(state);
        offset += rate;
    }

    // Pad and final block
    const remaining = message.length - offset;
    const padded = new Uint8Array(rate);
    if (remaining > 0) {
        padded.set(message.slice(offset));
    }
    padded[remaining] = 0x06; // SHA3 domain separator
    padded[rate - 1] = (padded[rate - 1] ?? 0) | 0x80; // Final bit

    xorBytes(state, padded);
    keccakF(state);

    // Squeeze
    const output = lanesToBytes(state, outputLen);

    return '0x' + Array.from(output)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Compute SHA3-256 hash and return raw bytes
 * @param input - String or Uint8Array to hash
 * @returns Raw hash bytes
 */
export function sha3Bytes(input: string | Uint8Array): Uint8Array {
    const hex = sha3(input).slice(2);
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

/**
 * Concatenate multiple values and hash
 * @param values - Array of strings or byte arrays to concatenate and hash
 * @returns Hex-encoded hash string prefixed with 0x
 */
export function sha3Concat(...values: (string | Uint8Array | null)[]): string {
    const parts: Uint8Array[] = [];
    const encoder = new TextEncoder();
    const separator = encoder.encode('||');

    for (const value of values) {
        if (value === null) {
            parts.push(encoder.encode('null'));
        } else if (typeof value === 'string') {
            parts.push(encoder.encode(value));
        } else {
            parts.push(value);
        }
        parts.push(separator);
    }

    let totalLength = 0;
    for (const p of parts) {
        totalLength += p.length;
    }

    const combined = new Uint8Array(totalLength);
    let offset = 0;
    for (const part of parts) {
        combined.set(part, offset);
        offset += part.length;
    }

    return sha3(combined);
}
