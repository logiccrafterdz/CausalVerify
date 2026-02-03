/**
 * Main entry point tests
 * Validates all exports are functional
 */

import { describe, it, expect } from 'vitest';
import {
    // Types - just verify they can be imported
    sha3,
    sha3Bytes,
    sha3Concat,
    generateUUIDv7,
    extractTimestamp,
    isValidUUIDv7,
    compareUUIDv7,
    MerkleTree,
    CausalEventRegistry
} from './index.js';

describe('Main exports', () => {
    it('should export sha3 functions', () => {
        expect(typeof sha3).toBe('function');
        expect(typeof sha3Bytes).toBe('function');
        expect(typeof sha3Concat).toBe('function');
    });

    it('should export UUID functions', () => {
        expect(typeof generateUUIDv7).toBe('function');
        expect(typeof extractTimestamp).toBe('function');
        expect(typeof isValidUUIDv7).toBe('function');
        expect(typeof compareUUIDv7).toBe('function');
    });

    it('should export MerkleTree class', () => {
        expect(typeof MerkleTree).toBe('function');
        const tree = new MerkleTree();
        expect(tree).toBeInstanceOf(MerkleTree);
    });

    it('should export CausalEventRegistry class', () => {
        expect(typeof CausalEventRegistry).toBe('function');
        const registry = new CausalEventRegistry('0x123');
        expect(registry).toBeInstanceOf(CausalEventRegistry);
    });

    it('should work end-to-end', () => {
        const registry = new CausalEventRegistry('0xAgent1');

        const event1 = registry.registerEvent({
            agentId: '0xAgent1',
            actionType: 'request',
            payloadHash: sha3('request-payload'),
            predecessorHash: null,
            timestamp: Date.now()
        });

        expect(event1.causalEventId).toBeTruthy();
        expect(event1.eventHash).toMatch(/^0x[a-f0-9]{64}$/);
        expect(event1.treeRootHash).toMatch(/^0x[a-f0-9]{64}$/);

        // Verify the event is in the registry
        const retrieved = registry.getEvent(event1.causalEventId);
        expect(retrieved).toEqual(event1);

        // Verify Merkle inclusion
        expect(registry.verifyEventInclusion(event1.eventHash)).toBe(true);
    });
});
