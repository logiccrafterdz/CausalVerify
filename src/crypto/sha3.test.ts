/**
 * SHA3-256 Tests
 * Validates against known test vectors
 */

import { describe, it, expect } from 'vitest';
import { sha3, sha3Bytes, sha3Concat } from './sha3.js';

describe('SHA3-256', () => {
    describe('sha3', () => {
        it('should hash empty string correctly', () => {
            // Known SHA3-256 of empty string
            const hash = sha3('');
            expect(hash).toMatch(/^0x[a-f0-9]{64}$/);
            // SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
            expect(hash).toBe('0xa7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a');
        });

        it('should hash "abc" correctly', () => {
            // Known SHA3-256 of "abc"
            const hash = sha3('abc');
            expect(hash).toBe('0x3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532');
        });

        it('should produce different hashes for different inputs', () => {
            const hash1 = sha3('hello');
            const hash2 = sha3('hello!');
            expect(hash1).not.toBe(hash2);
        });

        it('should produce consistent hashes for same input', () => {
            const hash1 = sha3('test input');
            const hash2 = sha3('test input');
            expect(hash1).toBe(hash2);
        });

        it('should handle Uint8Array input', () => {
            const bytes = new TextEncoder().encode('abc');
            const hash = sha3(bytes);
            expect(hash).toBe('0x3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532');
        });

        it('should handle long inputs', () => {
            const longInput = 'a'.repeat(1000);
            const hash = sha3(longInput);
            expect(hash).toMatch(/^0x[a-f0-9]{64}$/);
        });

        it('should handle unicode characters', () => {
            const hash = sha3('hello world');
            expect(hash).toMatch(/^0x[a-f0-9]{64}$/);
        });
    });

    describe('sha3Bytes', () => {
        it('should return Uint8Array of 32 bytes', () => {
            const bytes = sha3Bytes('test');
            expect(bytes).toBeInstanceOf(Uint8Array);
            expect(bytes.length).toBe(32);
        });

        it('should match hex output of sha3', () => {
            const input = 'test';
            const hex = sha3(input).slice(2); // Remove 0x
            const bytes = sha3Bytes(input);

            const bytesHex = Array.from(bytes)
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');

            expect(bytesHex).toBe(hex);
        });
    });

    describe('sha3Concat', () => {
        it('should concatenate and hash multiple strings', () => {
            const hash = sha3Concat('a', 'b', 'c');
            expect(hash).toMatch(/^0x[a-f0-9]{64}$/);
        });

        it('should handle null values', () => {
            const hash = sha3Concat('a', null, 'b');
            expect(hash).toMatch(/^0x[a-f0-9]{64}$/);
        });

        it('should handle mixed string and Uint8Array', () => {
            const bytes = new Uint8Array([1, 2, 3]);
            const hash = sha3Concat('prefix', bytes, 'suffix');
            expect(hash).toMatch(/^0x[a-f0-9]{64}$/);
        });

        it('should produce consistent hashes with same inputs', () => {
            const hash1 = sha3Concat('a', 'b');
            const hash2 = sha3Concat('a', 'b');
            expect(hash1).toBe(hash2);
        });

        it('should produce different hashes for different order', () => {
            const hash1 = sha3Concat('a', 'b');
            const hash2 = sha3Concat('b', 'a');
            expect(hash1).not.toBe(hash2);
        });
    });
});
