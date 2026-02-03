import { describe, it, expect } from 'vitest';
import { ProofGenerator } from './generator.js';
import { CausalEventRegistry } from '../registry/registry.js';
import { generateKeyPair, sha3 } from '../crypto/index.js';

describe('ProofGenerator', () => {
    const agentId = '0xAgent';
    const { privateKey } = generateKeyPair();

    it('should throw error for non-existent event', () => {
        const registry = new CausalEventRegistry(agentId);
        const generator = new ProofGenerator(registry);
        expect(() => generator.generateProof('non-existent', privateKey)).toThrow('Event non-existent not found');
    });

    it('should handle missing proof path', () => {
        const registry = new CausalEventRegistry(agentId);
        const generator = new ProofGenerator(registry);
        // Register event without tree update (simulation)
        // We need to bypass CausalEventRegistry's internal state to simulate a mismatch
        // @ts-ignore
        registry.events.set('missing-path', {
            causalEventId: 'missing-path',
            agentId,
            positionInTree: 999 // Out of bounds
        });
        expect(() => generator.generateProof('missing-path', privateKey)).toThrow();
    });

    it('should generate valid proof', () => {
        const registry = new CausalEventRegistry(agentId);
        const event = registry.registerEvent({
            agentId,
            actionType: 'request',
            payloadHash: sha3('p'),
            predecessorHash: null,
            timestamp: Date.now()
        });
        const generator = new ProofGenerator(registry);
        const proof = generator.generateProof(event.causalEventId, privateKey);
        expect(proof.targetEvent.causalEventId).toBe(event.causalEventId);

        const proofs = generator.generateBatchProofs([event.causalEventId], privateKey);
        expect(proofs.length).toBe(1);
    });
});
