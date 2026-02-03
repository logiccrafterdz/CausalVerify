/**
 * x402 Integration Tests
 */

import { describe, it, expect } from 'vitest';
import { encodeCausalHeader, decodeCausalHeader, CAUSAL_PROOF_HEADER } from './x402.js';
import { CausalEventRegistry } from '../registry/registry.js';
import { ProofGenerator } from '../proof/generator.js';
import { generateKeyPair, sha3 } from '../crypto/index.js';

describe('x402 Integration', () => {
    const agentId = '0xAgent';
    const { privateKey } = generateKeyPair();

    it('should have the correct header name', () => {
        expect(CAUSAL_PROOF_HEADER).toBe('X-Causal-Proof');
    });

    it('should encode and decode a proof correctly', () => {
        const registry = new CausalEventRegistry(agentId);
        const generator = new ProofGenerator(registry);

        const event = registry.registerEvent({
            agentId,
            actionType: 'request',
            payloadHash: sha3('test'),
            predecessorHash: null,
            timestamp: Date.now()
        });

        const proof = generator.generateProof(event.causalEventId, privateKey);

        const headerValue = encodeCausalHeader(proof);
        expect(typeof headerValue).toBe('string');
        expect(headerValue.length).toBeGreaterThan(0);

        const decoded = decodeCausalHeader(headerValue);
        expect(decoded).toEqual(proof);
        expect(decoded.targetEvent.eventHash).toBe(event.eventHash);
    });

    it('should throw error for invalid encoding', () => {
        expect(() => decodeCausalHeader('invalid-base64!')).toThrow(/Failed to decode/);
    });

    it('should throw error for invalid JSON content', () => {
        const invalidBase64 = Buffer.from('not-json').toString('base64');
        expect(() => decodeCausalHeader(invalidBase64)).toThrow();
    });
});
