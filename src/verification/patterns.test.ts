/**
 * Verification Patterns Tests
 */

import { describe, it, expect } from 'vitest';
import { verifyPrePayment } from './patterns.js';
import { CausalEventRegistry } from '../registry/registry.js';
import { ProofGenerator } from '../proof/generator.js';
import { generateKeyPair, sha3 } from '../crypto/index.js';

describe('Verification Patterns', () => {
    const agentId = '0xAgent';
    const { privateKey, publicKey } = generateKeyPair();

    it('should verify pre-payment with semantic rules', () => {
        const registry = new CausalEventRegistry(agentId);
        const generator = new ProofGenerator(registry);

        // 1. Create a "response" without a "request"
        const event = registry.registerEvent({
            agentId,
            actionType: 'response',
            payloadHash: sha3('p1'),
            predecessorHash: null,
            timestamp: Date.now()
        });

        const proof = generator.generateProof(event.causalEventId, privateKey);

        // 2. Verify with rule: requestMustPrecedeResponse
        const result = verifyPrePayment(proof, agentId, publicKey, {
            requestMustPrecedeResponse: true
        });

        expect(result.isValid).toBe(false);
        expect(result.errors.some((e: string) => e.includes('Protocol violation'))).toBe(true);
        expect(result.trustScore).toBe(0.5); // Crypto valid, but semantic failed
    });

    it('should pass pre-payment when all rules match', () => {
        const registry = new CausalEventRegistry(agentId);
        const generator = new ProofGenerator(registry);

        const now = Date.now();
        const req = registry.registerEvent({
            agentId,
            actionType: 'request',
            payloadHash: sha3('q1'),
            predecessorHash: null,
            timestamp: now
        });

        const res = registry.registerEvent({
            agentId,
            actionType: 'response',
            payloadHash: sha3('a1'),
            predecessorHash: req.eventHash,
            timestamp: now + 500
        });

        const proof = generator.generateProof(res.causalEventId, privateKey);

        const result = verifyPrePayment(proof, agentId, publicKey, {
            requestMustPrecedeResponse: true,
            maxTimeGapMs: 1000
        });

        expect(result.isValid).toBe(true);
        // Trust score now uses granular calculation (0.2 base + chain length + recency)
        expect(result.trustScore).toBeGreaterThan(0.4);
    });
});
