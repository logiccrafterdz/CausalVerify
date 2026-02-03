/**
 * ECDSA secp256k1 Implementation
 * Pure JavaScript implementation of ECDSA using BigInt
 * Strictly compliant with BIP-62 for canonical signatures
 * @module crypto/ecdsa
 */

import { sha3 } from './sha3.js';

// secp256k1 curve parameters
const P = BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f');
const N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
const G = {
    x: BigInt('0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
    y: BigInt('0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8')
};

interface Point {
    x: bigint;
    y: bigint;
}

const INFINITY: Point = { x: 0n, y: 0n };

function isInfinity(P: Point): boolean {
    return P.x === 0n && P.y === 0n;
}

/**
 * Modular exponentiation (a^b mod p)
 */
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
    let res = 1n;
    base = base % mod;
    while (exp > 0n) {
        if (exp % 2n === 1n) res = (res * base) % mod;
        base = (base * base) % mod;
        exp = exp / 2n;
    }
    return res;
}

/**
 * Modular inverse using Fermat's Little Theorem (requires p to be prime)
 */
function modInverse(a: bigint, mod: bigint = N): bigint {
    return modPow(a, mod - 2n, mod);
}

/**
 * Convert hex string to BigInt
 */
function hexToBigInt(hex: string): bigint {
    const h = hex.startsWith('0x') ? hex.slice(2) : hex;
    if (h === '') return 0n;
    return BigInt('0x' + h);
}

/**
 * Point addition on secp256k1
 */
function pointAdd(p1: Point, p2: Point): Point {
    if (isInfinity(p1)) return p2;
    if (isInfinity(p2)) return p1;

    if (p1.x === p2.x) {
        if (p1.y !== p2.y) return INFINITY;
        // Point doubling
        const s = (3n * p1.x * p1.x * modInverse(2n * p1.y, P)) % P;
        const x3 = ((s * s - 2n * p1.x) % P + P) % P;
        const y3 = ((s * (p1.x - x3) - p1.y) % P + P) % P;
        return { x: x3, y: y3 };
    }

    // Point addition
    const s = ((p2.y - p1.y) * modInverse(p2.x - p1.x, P)) % P;
    const x3 = ((s * s - p1.x - p2.x) % P + P) % P;
    const y3 = ((s * (p1.x - x3) - p1.y) % P + P) % P;
    return { x: x3, y: y3 };
}

/**
 * Point multiplication (scalar multiplication) on secp256k1
 */
function pointMul(k: bigint, P: Point): Point {
    let result = INFINITY;
    let base = P;
    let scalar = k % N;
    while (scalar > 0n) {
        if (scalar % 2n === 1n) result = pointAdd(result, base);
        base = pointAdd(base, base);
        scalar = scalar / 2n;
    }
    return result;
}

/**
 * Generate a cryptographically secure private key
 */
export function generatePrivateKey(): string {
    const bytes = new Uint8Array(32);
    if (typeof crypto !== 'undefined') {
        crypto.getRandomValues(bytes);
    } else {
        // Fallback for environments without crypto
        for (let i = 0; i < 32; i++) bytes[i] = Math.floor(Math.random() * 256);
    }
    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    return '0x' + hex;
}

/**
 * Derive public key from private key
 */
export function getPublicKey(privateKey: string): string {
    const k = hexToBigInt(privateKey);
    const pubPoint = pointMul(k, G);
    const xHex = pubPoint.x.toString(16).padStart(64, '0');
    const yHex = pubPoint.y.toString(16).padStart(64, '0');
    return '0x04' + xHex + yHex;
}

/**
 * Generate a new key pair
 */
export function generateKeyPair(): { privateKey: string; publicKey: string } {
    const privateKey = generatePrivateKey();
    const publicKey = getPublicKey(privateKey);
    return { privateKey, publicKey };
}

/**
 * Sign a message hash
 * @param messageHash - SHA3-256 hash of the message
 * @param privateKey - Private key in hex format
 * @returns 64-byte signature in hex format (r + s)
 */
export function sign(messageHash: string, privateKey: string): string {
    const z = hexToBigInt(messageHash);
    const d = hexToBigInt(privateKey);

    let r = 0n;
    let s = 0n;

    while (r === 0n || s === 0n) {
        const k = hexToBigInt(generatePrivateKey());
        const R = pointMul(k, G);
        r = R.x % N;
        if (r === 0n) continue;

        const kInv = modInverse(k, N);
        s = (kInv * (z + r * d)) % N;

        // Ensure Low-S (BIP-62)
        if (s > N / 2n) {
            s = N - s;
        }
    }

    const rHex = r.toString(16).padStart(64, '0');
    const sHex = s.toString(16).padStart(64, '0');
    return '0x' + rHex + sHex;
}

/**
 * Verify a signature
 */
export function verify(messageHash: string, signature: string, publicKey: string): boolean {
    try {
        const z = hexToBigInt(messageHash);
        let sig = signature.startsWith('0x') ? signature.slice(2) : signature;
        if (sig.length !== 128) return false;

        const r = BigInt('0x' + sig.slice(0, 64));
        const s = BigInt('0x' + sig.slice(64, 128));

        if (r <= 0n || r >= N || s <= 0n || s >= N) return false;

        // BIP-62 High-S check
        if (s > N / 2n) return false;

        const point = parsePublicKey(publicKey);
        const sInv = modInverse(s, N);
        const u1 = (z * sInv) % N;
        const u2 = (r * sInv) % N;

        const p1 = pointMul(u1, G);
        const p2 = pointMul(u2, point);
        const R = pointAdd(p1, p2);

        if (isInfinity(R)) return false;
        return (R.x % N) === r;
    } catch {
        return false;
    }
}

/**
 * Recover public key from signature
 */
export function recoverPublicKey(
    messageHash: string,
    signature: string,
    recoveryId: 0 | 1 = 0
): string | null {
    if (recoveryId !== 0 && recoveryId !== 1) return null;
    try {
        const z = hexToBigInt(messageHash);
        let sig = signature.startsWith('0x') ? signature.slice(2) : signature;
        if (sig.length !== 128) return null;

        const r = BigInt('0x' + sig.slice(0, 64));
        const s = BigInt('0x' + sig.slice(64, 128));

        const x = r;
        const y2 = (modPow(x, 3n, P) + 7n) % P;
        let y = modPow(y2, (P + 1n) / 4n, P);

        if ((y & 1n) !== BigInt(recoveryId)) y = P - y;

        const R = { x, y };
        // Check if R is on curve
        if ((y * y) % P !== y2) return null;

        const rInv = modInverse(r, N);
        const u1 = (((N - z) % N) * rInv) % N;
        const u2 = (s * rInv) % N;

        const pubPoint = pointAdd(pointMul(u1, G), pointMul(u2, R));
        if (isInfinity(pubPoint)) return null;

        const xHex = pubPoint.x.toString(16).padStart(64, '0');
        const yHex = pubPoint.y.toString(16).padStart(64, '0');
        return '0x04' + xHex + yHex;
    } catch {
        return null;
    }
}

function parsePublicKey(pubKey: string): Point {
    const k = pubKey.startsWith('0x') ? pubKey.slice(2) : pubKey;
    if (k.length !== 130 || !k.startsWith('04')) throw new Error('Invalid public key format');
    return {
        x: BigInt('0x' + k.slice(2, 66)),
        y: BigInt('0x' + k.slice(66, 130))
    };
}

export function isValidPrivateKey(privateKey: string): boolean {
    try {
        const k = hexToBigInt(privateKey);
        return k > 0n && k < N;
    } catch {
        return false;
    }
}

export function isValidPublicKey(publicKey: string): boolean {
    try {
        const p = parsePublicKey(publicKey);
        return (p.y * p.y) % P === (modPow(p.x, 3n, P) + 7n) % P;
    } catch {
        return false;
    }
}
