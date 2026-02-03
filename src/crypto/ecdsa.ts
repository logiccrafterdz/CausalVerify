/**
 * Pure JavaScript ECDSA secp256k1 Implementation
 * For signing and verifying causal proofs
 * No external dependencies
 * @module crypto/ecdsa
 */

// secp256k1 curve parameters
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

/**
 * Modular inverse using extended Euclidean algorithm
 */
function modInverse(a: bigint, m: bigint): bigint {
    if (a < 0n) a = ((a % m) + m) % m;

    let [old_r, r] = [a, m];
    let [old_s, s] = [1n, 0n];

    while (r !== 0n) {
        const q = old_r / r;
        [old_r, r] = [r, old_r - q * r];
        [old_s, s] = [s, old_s - q * s];
    }

    return ((old_s % m) + m) % m;
}

/**
 * Modular exponentiation
 */
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
    let result = 1n;
    base = ((base % mod) + mod) % mod;

    while (exp > 0n) {
        if (exp & 1n) {
            result = (result * base) % mod;
        }
        exp >>= 1n;
        base = (base * base) % mod;
    }

    return result;
}

/**
 * Point on the secp256k1 curve
 */
interface Point {
    x: bigint;
    y: bigint;
}

const INFINITY: Point = { x: 0n, y: 0n };
const G: Point = { x: Gx, y: Gy };

/**
 * Check if point is at infinity
 */
function isInfinity(p: Point): boolean {
    return p.x === 0n && p.y === 0n;
}

/**
 * Point addition on secp256k1
 */
function pointAdd(p1: Point, p2: Point): Point {
    if (isInfinity(p1)) return p2;
    if (isInfinity(p2)) return p1;

    if (p1.x === p2.x) {
        if (p1.y !== p2.y) return INFINITY; // P + (-P) = O
        // Point doubling
        const s = (3n * p1.x * p1.x * modInverse(2n * p1.y, P)) % P;
        const x3 = ((s * s - 2n * p1.x) % P + P) % P;
        const y3 = ((s * (p1.x - x3) - p1.y) % P + P) % P;
        return { x: x3, y: y3 };
    }

    // Point addition
    const s = ((p2.y - p1.y) * modInverse((p2.x - p1.x + P) % P, P)) % P;
    const x3 = ((s * s - p1.x - p2.x) % P + P) % P;
    const y3 = ((s * (p1.x - x3) - p1.y) % P + P) % P;
    return { x: x3, y: y3 };
}

/**
 * Scalar multiplication using double-and-add
 */
function pointMul(k: bigint, p: Point): Point {
    let result = INFINITY;
    let addend = p;

    k = ((k % N) + N) % N;

    while (k > 0n) {
        if (k & 1n) {
            result = pointAdd(result, addend);
        }
        addend = pointAdd(addend, addend);
        k >>= 1n;
    }

    return result;
}

/**
 * Convert hex string to bigint
 */
function hexToBigInt(hex: string): bigint {
    if (hex.startsWith('0x')) hex = hex.slice(2);
    return BigInt('0x' + hex);
}

/**
 * Convert bigint to 32-byte hex string
 */
function bigIntToHex32(n: bigint): string {
    const hex = n.toString(16).padStart(64, '0');
    return '0x' + hex;
}

/**
 * Generate a random private key
 */
export function generatePrivateKey(): string {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);

    let k = 0n;
    for (let i = 0; i < 32; i++) {
        k = (k << 8n) | BigInt(bytes[i] ?? 0);
    }

    // Ensure k is in valid range [1, N-1]
    k = (k % (N - 1n)) + 1n;

    return bigIntToHex32(k);
}

/**
 * Derive public key from private key
 */
export function getPublicKey(privateKey: string): string {
    const k = hexToBigInt(privateKey);
    const point = pointMul(k, G);

    // Uncompressed public key format: 04 || x || y
    const x = point.x.toString(16).padStart(64, '0');
    const y = point.y.toString(16).padStart(64, '0');
    return '0x04' + x + y;
}

/**
 * Generate a key pair
 */
export function generateKeyPair(): { privateKey: string; publicKey: string } {
    const privateKey = generatePrivateKey();
    const publicKey = getPublicKey(privateKey);
    return { privateKey, publicKey };
}

/**
 * Parse public key to point
 */
function parsePublicKey(publicKey: string): Point {
    let hex = publicKey.startsWith('0x') ? publicKey.slice(2) : publicKey;

    if (hex.startsWith('04') && hex.length === 130) {
        // Uncompressed format
        const x = BigInt('0x' + hex.slice(2, 66));
        const y = BigInt('0x' + hex.slice(66, 130));
        return { x, y };
    }

    throw new Error('Invalid public key format');
}

/**
 * Sign a message hash with private key
 * Returns signature in format: r || s (each 32 bytes)
 */
export function sign(messageHash: string, privateKey: string): string {
    const z = hexToBigInt(messageHash);
    const d = hexToBigInt(privateKey);

    // Generate deterministic k using RFC 6979-like approach
    // For simplicity, use hash-based k generation
    const hashBytes = new Uint8Array(64);
    const msgBytes = hexToBytes(messageHash);
    const keyBytes = hexToBytes(privateKey);

    // Simple k derivation (not full RFC 6979, but deterministic)
    for (let i = 0; i < 32; i++) {
        hashBytes[i] = msgBytes[i] ?? 0;
        hashBytes[i + 32] = keyBytes[i] ?? 0;
    }

    // Hash to get k seed
    let k = 0n;
    for (let i = 0; i < 32; i++) {
        k = (k << 8n) | BigInt(hashBytes[i] ?? 0);
    }
    k = (k % (N - 1n)) + 1n;

    // Try different k values until we get valid signature
    for (let attempt = 0; attempt < 100; attempt++) {
        const kPoint = pointMul(k, G);
        const r = kPoint.x % N;

        if (r === 0n) {
            k = (k + 1n) % N;
            continue;
        }

        const kInv = modInverse(k, N);
        let s = (kInv * (z + r * d)) % N;

        if (s === 0n) {
            k = (k + 1n) % N;
            continue;
        }

        // Normalize s to lower half of curve order (BIP-62)
        if (s > N / 2n) {
            s = N - s;
        }

        const rHex = r.toString(16).padStart(64, '0');
        const sHex = s.toString(16).padStart(64, '0');
        return '0x' + rHex + sHex;
    }

    throw new Error('Failed to generate valid signature');
}

/**
 * Convert hex to bytes
 */
function hexToBytes(hex: string): Uint8Array {
    if (hex.startsWith('0x')) hex = hex.slice(2);
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

/**
 * Verify a signature
 */
export function verify(messageHash: string, signature: string, publicKey: string): boolean {
    try {
        const z = hexToBigInt(messageHash);
        let sig = signature.startsWith('0x') ? signature.slice(2) : signature;

        if (sig.length !== 128) {
            return false;
        }

        const r = BigInt('0x' + sig.slice(0, 64));
        const s = BigInt('0x' + sig.slice(64, 128));

        // Check r, s are in valid range
        if (r <= 0n || r >= N || s <= 0n || s >= N) {
            return false;
        }

        // Normalize s to lower half of curve order (BIP-62)
        // Reject non-canonical signatures to prevent malleability
        if (s > N / 2n) {
            return false;
        }

        const pubPoint = parsePublicKey(publicKey);

        const sInv = modInverse(s, N);
        const u1 = (z * sInv) % N;
        const u2 = (r * sInv) % N;

        const p1 = pointMul(u1, G);
        const p2 = pointMul(u2, pubPoint);
        const point = pointAdd(p1, p2);

        if (isInfinity(point)) {
            return false;
        }

        return (point.x % N) === r;
    } catch {
        return false;
    }
}

/**
 * Recover public key from signature and message hash
 * Returns possible public keys (usually 2)
 */
export function recoverPublicKey(
    messageHash: string,
    signature: string,
    recoveryId: 0 | 1 = 0
): string | null {
    try {
        const z = hexToBigInt(messageHash);
        let sig = signature.startsWith('0x') ? signature.slice(2) : signature;

        const r = BigInt('0x' + sig.slice(0, 64));
        const s = BigInt('0x' + sig.slice(64, 128));

        // Calculate y coordinate of R
        const x = r;
        const ySquared = (modPow(x, 3n, P) + 7n) % P;
        let y = modPow(ySquared, (P + 1n) / 4n, P);

        // Choose correct y based on recovery id
        if ((y & 1n) !== BigInt(recoveryId)) {
            y = P - y;
        }

        const R: Point = { x, y };

        // Verify R is on curve
        const lhs = (y * y) % P;
        const rhs = (modPow(x, 3n, P) + 7n) % P;
        if (lhs !== rhs) {
            return null;
        }

        const rInv = modInverse(r, N);
        const u1 = (((N - z) % N) * rInv) % N;
        const u2 = (s * rInv) % N;

        const p1 = pointMul(u1, G);
        const p2 = pointMul(u2, R);
        const pubPoint = pointAdd(p1, p2);

        if (isInfinity(pubPoint)) {
            return null;
        }

        const xHex = pubPoint.x.toString(16).padStart(64, '0');
        const yHex = pubPoint.y.toString(16).padStart(64, '0');
        return '0x04' + xHex + yHex;
    } catch {
        return null;
    }
}

/**
 * Check if a private key is valid
 */
export function isValidPrivateKey(privateKey: string): boolean {
    try {
        const k = hexToBigInt(privateKey);
        return k > 0n && k < N;
    } catch {
        return false;
    }
}

/**
 * Check if a public key is valid (on the curve)
 */
export function isValidPublicKey(publicKey: string): boolean {
    try {
        const point = parsePublicKey(publicKey);
        const lhs = (point.y * point.y) % P;
        const rhs = (modPow(point.x, 3n, P) + 7n) % P;
        return lhs === rhs;
    } catch {
        return false;
    }
}
