/**
 * UUIDv7 Tests
 * Validates RFC 9562 compliance
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { generateUUIDv7, extractTimestamp, isValidUUIDv7, compareUUIDv7 } from './uuid.js';

describe('UUIDv7', () => {
    describe('generateUUIDv7', () => {
        it('should generate valid UUIDv7 format', () => {
            const uuid = generateUUIDv7();
            expect(isValidUUIDv7(uuid)).toBe(true);
        });

        it('should generate unique UUIDs', () => {
            const uuids = new Set<string>();
            for (let i = 0; i < 1000; i++) {
                uuids.add(generateUUIDv7());
            }
            expect(uuids.size).toBe(1000);
        });

        it('should have version 7 in correct position', () => {
            const uuid = generateUUIDv7();
            // Position 12 should be '7'
            expect(uuid.charAt(14)).toBe('7');
        });

        it('should have variant bits in correct position', () => {
            const uuid = generateUUIDv7();
            // Position 16 should be 8, 9, a, or b
            const variant = uuid.charAt(19);
            expect(['8', '9', 'a', 'b']).toContain(variant.toLowerCase());
        });

        it('should be temporally ordered', async () => {
            const uuid1 = generateUUIDv7();
            // Small delay to ensure different timestamp
            await new Promise(resolve => setTimeout(resolve, 2));
            const uuid2 = generateUUIDv7();

            expect(compareUUIDv7(uuid1, uuid2)).toBe(-1);
        });
    });

    describe('extractTimestamp', () => {
        it('should extract timestamp close to current time', () => {
            const before = Date.now();
            const uuid = generateUUIDv7();
            const after = Date.now();

            const timestamp = extractTimestamp(uuid);

            expect(timestamp).toBeGreaterThanOrEqual(before);
            expect(timestamp).toBeLessThanOrEqual(after);
        });

        it('should handle UUID with dashes', () => {
            const uuid = generateUUIDv7();
            const timestamp = extractTimestamp(uuid);
            expect(typeof timestamp).toBe('number');
            expect(timestamp).toBeGreaterThan(0);
        });
    });

    describe('isValidUUIDv7', () => {
        it('should validate correct UUIDv7', () => {
            const uuid = generateUUIDv7();
            expect(isValidUUIDv7(uuid)).toBe(true);
        });

        it('should reject invalid format', () => {
            expect(isValidUUIDv7('not-a-uuid')).toBe(false);
        });

        it('should reject UUIDv4', () => {
            // UUIDv4 example
            expect(isValidUUIDv7('550e8400-e29b-41d4-a716-446655440000')).toBe(false);
        });

        it('should reject empty string', () => {
            expect(isValidUUIDv7('')).toBe(false);
        });

        it('should be case insensitive', () => {
            const uuid = generateUUIDv7().toUpperCase();
            expect(isValidUUIDv7(uuid)).toBe(true);
        });
    });

    describe('compareUUIDv7', () => {
        it('should return 0 for identical UUIDs', () => {
            const uuid = generateUUIDv7();
            expect(compareUUIDv7(uuid, uuid)).toBe(0);
        });

        it('should return -1 when first is earlier', async () => {
            const uuid1 = generateUUIDv7();
            await new Promise(resolve => setTimeout(resolve, 2));
            const uuid2 = generateUUIDv7();

            expect(compareUUIDv7(uuid1, uuid2)).toBe(-1);
        });

        it('should return 1 when first is later', async () => {
            const uuid1 = generateUUIDv7();
            await new Promise(resolve => setTimeout(resolve, 2));
            const uuid2 = generateUUIDv7();

            expect(compareUUIDv7(uuid2, uuid1)).toBe(1);
        });

        it('should handle case differences', () => {
            const uuid = generateUUIDv7();
            expect(compareUUIDv7(uuid.toUpperCase(), uuid.toLowerCase())).toBe(0);
        });
    });

    describe('environment fallback', () => {
        it('should fallback to Math.random if crypto is unavailable', () => {
            const originalCrypto = global.crypto;
            try {
                // @ts-ignore
                delete global.crypto;
                const uuid = generateUUIDv7();
                expect(isValidUUIDv7(uuid)).toBe(true);
            } finally {
                global.crypto = originalCrypto;
            }
        });
    });
});
