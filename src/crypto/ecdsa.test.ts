/**
 * ECDSA secp256k1 Tests
 */

import { describe, it, expect } from 'vitest';
import {
    generatePrivateKey,
    generateKeyPair,
    getPublicKey,
    sign,
    verify,
    recoverPublicKey,
    isValidPrivateKey,
    isValidPublicKey
} from './ecdsa.js';
import { sha3 } from './sha3.js';

describe('ECDSA secp256k1', () => {
    describe('generatePrivateKey', () => {
        it('should generate valid 32-byte hex private key', () => {
            const key = generatePrivateKey();
            expect(key).toMatch(/^0x[a-f0-9]{64}$/);
        });

        it('should generate unique keys', () => {
            const keys = new Set<string>();
            for (let i = 0; i < 10; i++) {
                keys.add(generatePrivateKey());
            }
            expect(keys.size).toBe(10);
        });

        it('should generate valid private keys', () => {
            for (let i = 0; i < 5; i++) {
                const key = generatePrivateKey();
                expect(isValidPrivateKey(key)).toBe(true);
            }
        });
    });

    describe('getPublicKey', () => {
        it('should derive public key from private key', () => {
            const privateKey = generatePrivateKey();
            const publicKey = getPublicKey(privateKey);

            // Uncompressed format: 04 + 64 bytes x + 64 bytes y
            expect(publicKey).toMatch(/^0x04[a-f0-9]{128}$/);
        });

        it('should derive consistent public key', () => {
            const privateKey = generatePrivateKey();
            const pub1 = getPublicKey(privateKey);
            const pub2 = getPublicKey(privateKey);
            expect(pub1).toBe(pub2);
        });
    });

    describe('generateKeyPair', () => {
        it('should generate matching key pair', () => {
            const { privateKey, publicKey } = generateKeyPair();
            expect(getPublicKey(privateKey)).toBe(publicKey);
        });
    });

    describe('sign', () => {
        it('should produce valid signature format', () => {
            const { privateKey } = generateKeyPair();
            const messageHash = sha3('test message');
            const signature = sign(messageHash, privateKey);

            // r (32 bytes) + s (32 bytes)
            expect(signature).toMatch(/^0x[a-f0-9]{128}$/);
        });

        it('should produce deterministic signatures', () => {
            const { privateKey } = generateKeyPair();
            const messageHash = sha3('test');

            const sig1 = sign(messageHash, privateKey);
            const sig2 = sign(messageHash, privateKey);
            expect(sig1).toBe(sig2);
        });

        it('should produce different signatures for different messages', () => {
            const { privateKey } = generateKeyPair();
            const sig1 = sign(sha3('message1'), privateKey);
            const sig2 = sign(sha3('message2'), privateKey);
            expect(sig1).not.toBe(sig2);
        });
    });

    describe('verify', () => {
        it('should verify valid signature', () => {
            const { privateKey, publicKey } = generateKeyPair();
            const messageHash = sha3('test message');
            const signature = sign(messageHash, privateKey);

            expect(verify(messageHash, signature, publicKey)).toBe(true);
        });

        it('should reject signature with wrong message', () => {
            const { privateKey, publicKey } = generateKeyPair();
            const signature = sign(sha3('original'), privateKey);

            expect(verify(sha3('different'), signature, publicKey)).toBe(false);
        });

        it('should reject signature with wrong public key', () => {
            const keyPair1 = generateKeyPair();
            const keyPair2 = generateKeyPair();

            const messageHash = sha3('test');
            const signature = sign(messageHash, keyPair1.privateKey);

            expect(verify(messageHash, signature, keyPair2.publicKey)).toBe(false);
        });

        it('should reject tampered signature', () => {
            const { privateKey, publicKey } = generateKeyPair();
            const messageHash = sha3('test');
            const signature = sign(messageHash, privateKey);

            // Tamper with signature
            const tampered = signature.slice(0, -2) + '00';
            expect(verify(messageHash, tampered, publicKey)).toBe(false);
        });

        it('should reject invalid signature format', () => {
            const { publicKey } = generateKeyPair();
            const messageHash = sha3('test');

            expect(verify(messageHash, '0x1234', publicKey)).toBe(false);
            expect(verify(messageHash, 'invalid', publicKey)).toBe(false);
        });

        it('should reject non-canonical (High-S) signatures', () => {
            const { privateKey, publicKey } = generateKeyPair();
            const messageHash = sha3('test');

            // Generate a valid signature
            const sig = sign(messageHash, privateKey);
            const r = BigInt(sig.slice(0, 66));
            let s = BigInt('0x' + sig.slice(66));

            // Force high-S (N - s)
            const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
            const highS = N - s;
            const highSig = '0x' + r.toString(16).padStart(64, '0') + highS.toString(16).padStart(64, '0');

            // Signature verification should fail for high-S (BIP-62)
            expect(verify(messageHash, highSig, publicKey)).toBe(false);
        });
    });

    describe('recoverPublicKey', () => {
        it('should recover public key from signature', () => {
            const { privateKey, publicKey } = generateKeyPair();
            const messageHash = sha3('test message');
            const signature = sign(messageHash, privateKey);

            // Try both recovery IDs
            const recovered0 = recoverPublicKey(messageHash, signature, 0);
            const recovered1 = recoverPublicKey(messageHash, signature, 1);

            // One of them should match
            const matches = recovered0 === publicKey || recovered1 === publicKey;
            expect(matches).toBe(true);
        });
    });

    describe('isValidPrivateKey', () => {
        it('should accept valid private keys', () => {
            expect(isValidPrivateKey(generatePrivateKey())).toBe(true);
        });

        it('should reject zero', () => {
            expect(isValidPrivateKey('0x' + '0'.repeat(64))).toBe(false);
        });

        it('should reject invalid format', () => {
            expect(isValidPrivateKey('invalid')).toBe(false);
        });
    });

    describe('isValidPublicKey', () => {
        it('should accept valid public keys', () => {
            const { publicKey } = generateKeyPair();
            expect(isValidPublicKey(publicKey)).toBe(true);
        });

        it('should reject invalid public keys', () => {
            expect(isValidPublicKey('0x04' + '0'.repeat(128))).toBe(false);
        });

        it('should reject invalid format', () => {
            expect(isValidPublicKey('invalid')).toBe(false);
        });
    });

    describe('end-to-end signing flow', () => {
        it('should work for multiple messages', () => {
            const { privateKey, publicKey } = generateKeyPair();

            const messages = ['hello', 'world', 'test', 'causal', 'verify'];

            for (const msg of messages) {
                const hash = sha3(msg);
                const sig = sign(hash, privateKey);
                expect(verify(hash, sig, publicKey)).toBe(true);
            }
        });
    });
});
