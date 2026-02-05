/**
 * x402 Integration Tests
 */

import { describe, it, expect } from 'vitest';
import {
    encodeCausalHeader,
    decodeCausalHeader,
    isValidCausalProof,
    CAUSAL_PROOF_HEADER,
    CAUSAL_PROOF_SCHEMA_HEADER,
    CAUSAL_PROOF_SCHEMA_VERSION
} from './x402.js';
import { CausalEventRegistry } from '../registry/registry.js';
import { ProofGenerator } from '../proof/generator.js';
import { generateKeyPair, sha3 } from '../crypto/index.js';

describe('x402 Integration', () => {
    const agentId = '0xAgent';
    const { privateKey } = generateKeyPair();

    it('should have the correct header names and version', () => {
        expect(CAUSAL_PROOF_HEADER).toBe('X-Causal-Proof');
        expect(CAUSAL_PROOF_SCHEMA_HEADER).toBe('X-Causal-Proof-Schema');
        expect(CAUSAL_PROOF_SCHEMA_VERSION).toBe('causal-v1');
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
        const invalidBase64 = btoa('not-json');
        expect(() => decodeCausalHeader(invalidBase64)).toThrow();
    });

    it('should handle malformed base64 without crashing', () => {
        expect(() => decodeCausalHeader('!!!???')).toThrow();
    });

    it('should reject undersized or missing required fields with schema validation', () => {
        const partialData = btoa(JSON.stringify({ targetEvent: {} }));
        // Now throws because schema validation rejects incomplete structure
        expect(() => decodeCausalHeader(partialData)).toThrow(/Invalid CausalProof structure/);
    });

    describe('isValidCausalProof', () => {
        it('should reject null', () => {
            expect(isValidCausalProof(null)).toBe(false);
        });

        it('should reject non-objects', () => {
            expect(isValidCausalProof('string')).toBe(false);
            expect(isValidCausalProof(123)).toBe(false);
        });

        it('should reject incomplete proofs', () => {
            expect(isValidCausalProof({ targetEvent: {} })).toBe(false);
            expect(isValidCausalProof({ targetEvent: {}, proofPath: [] })).toBe(false);
        });

        it('should accept valid proof structure', () => {
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
            expect(isValidCausalProof(proof)).toBe(true);
        });
    });
});

