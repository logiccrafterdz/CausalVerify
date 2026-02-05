/**
 * ECDSA secp256k1 Tests
 */

import { describe, it, expect } from 'vitest';
import {
    generateKeyPair,
    sign,
    verify,
    recoverPublicKey,
    isValidPrivateKey,
    isValidPublicKey,
    generatePrivateKey
} from './ecdsa.js';
import { sha3 } from './sha3.js';

describe('ECDSA secp256k1', () => {
    describe('comprehensive coverage', () => {
        it('should sign and verify', () => {
            const { privateKey, publicKey } = generateKeyPair();
            const msg = sha3('test');
            const sig = sign(msg, privateKey);
            expect(verify(msg, sig, publicKey)).toBe(true);
        });

        it('should hit all catch blocks and invalid formats', () => {
            const { publicKey } = generateKeyPair();
            const msg = sha3('t');

            // isValidPrivateKey catch
            // @ts-ignore
            expect(isValidPrivateKey(null)).toBe(false);

            // isValidPublicKey catch
            // @ts-ignore
            expect(isValidPublicKey(null)).toBe(false);

            // recoverPublicKey catch
            // @ts-ignore
            expect(recoverPublicKey(null, null, 0)).toBeNull();

            // hexToBigInt empty
            // @ts-ignore
            expect(recoverPublicKey('', '', 0)).toBeNull();

            // Invalid formats
            expect(isValidPublicKey('0x04' + '0'.repeat(128))).toBe(false);
            expect(isValidPublicKey('0x0400')).toBe(false);
            expect(isValidPublicKey('0x03' + '0'.repeat(128))).toBe(false);
            expect(isValidPublicKey('0x04' + '1'.repeat(128))).toBe(false);

            // Recovery ID OOB
            // @ts-ignore
            expect(recoverPublicKey(msg, '0x' + '0'.repeat(128), 2)).toBeNull();

            // Signature length mismatch
            expect(verify(msg, '0x00', publicKey)).toBe(false);
            expect(recoverPublicKey(msg, '0x00', 0)).toBeNull();

            // verify catch
            // @ts-ignore
            expect(verify(null, null, null)).toBe(false);
        });

        it('should exercise mathematical branches', () => {
            // force point reconstruction failure
            for (let i = 1; i < 20; i++) {
                const sig = '0x' + i.toString(16).padStart(64, '0') + 'f'.repeat(64);
                recoverPublicKey(sha3('t'), sig, 0);
            }
        });

        it('should throw error if crypto is unavailable', () => {
            const originalCrypto = globalThis.crypto;
            // @ts-ignore
            delete globalThis.crypto;
            expect(() => generatePrivateKey()).toThrow('Secure random number generator unavailable');
            globalThis.crypto = originalCrypto;
        });

        it('should reject high-S signatures', () => {
            const { privateKey, publicKey } = generateKeyPair();
            const msg = sha3('test');
            const sig = sign(msg, privateKey);
            const r = sig.slice(2, 66);
            const s = BigInt('0x' + sig.slice(66, 130));
            const N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
            const highSig = '0x' + r + (N - s).toString(16).padStart(64, '0');
            expect(verify(msg, highSig, publicKey)).toBe(false);
        });
    });
});
