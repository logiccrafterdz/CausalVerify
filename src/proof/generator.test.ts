/**
 * Proof Generator Tests
 */

import { describe, it, expect } from 'vitest';
import { ProofGenerator } from './generator.js';
import { CausalEventRegistry } from '../registry/registry.js';
import { generateKeyPair, sha3 } from '../crypto/index.js';

describe('ProofGenerator', () => {
    const agentId = '0xAgent';
    const { privateKey, publicKey } = generateKeyPair();

    it('should generate a valid causal proof', () => {
        const registry = new CausalEventRegistry(agentId);
        const generator = new ProofGenerator(registry);

        const event = registry.registerEvent({
            agentId,
            actionType: 'request',
            payloadHash: sha3('payload'),
            predecessorHash: null,
            timestamp: Date.now()
        });

        const proof = generator.generateProof(event.causalEventId, privateKey);

        expect(proof.targetEvent).toEqual(event);
        expect(proof.treeRootHash).toBe(registry.getRootHash());
        expect(proof.causalChain.length).toBe(1);
        expect(proof.causalChain[0].eventHash).toBe(event.eventHash);
        expect(proof.agentSignature).toBeTruthy();
    });

    it('should include correct causal chain depth', () => {
        const registry = new CausalEventRegistry(agentId);
        const generator = new ProofGenerator(registry);

        const event1 = registry.registerEvent({
            agentId,
            actionType: 'request',
            payloadHash: sha3('p1'),
            predecessorHash: null,
            timestamp: Date.now()
        });

        const event2 = registry.registerEvent({
            agentId,
            actionType: 'response',
            payloadHash: sha3('p2'),
            predecessorHash: event1.eventHash,
            timestamp: Date.now()
        });

        const proof = generator.generateProof(event2.causalEventId, privateKey, 1);

        expect(proof.causalChain.length).toBe(1);
        expect(proof.causalChain[0].eventHash).toBe(event2.eventHash);

        const fullProof = generator.generateProof(event2.causalEventId, privateKey);
        expect(fullProof.causalChain.length).toBe(2);
        expect(fullProof.causalChain[0].eventHash).toBe(event1.eventHash);
        expect(fullProof.causalChain[1].eventHash).toBe(event2.eventHash);
    });

    it('should throw error if event not found', () => {
        const registry = new CausalEventRegistry(agentId);
        const generator = new ProofGenerator(registry);

        expect(() => generator.generateProof('non-existent', privateKey)).toThrow();
    });

    it('should generate batch proofs', () => {
        const registry = new CausalEventRegistry(agentId);
        const generator = new ProofGenerator(registry);

        const e1 = registry.registerEvent({
            agentId,
            actionType: 'request',
            payloadHash: sha3('p1'),
            predecessorHash: null,
            timestamp: Date.now()
        });

        const e2 = registry.registerEvent({
            agentId,
            actionType: 'request',
            payloadHash: sha3('p2'),
            predecessorHash: null,
            timestamp: Date.now()
        });

        const proofs = generator.generateBatchProofs([e1.causalEventId, e2.causalEventId], privateKey);
        expect(proofs.length).toBe(2);
        expect(proofs[0].targetEvent.causalEventId).toBe(e1.causalEventId);
        expect(proofs[1].targetEvent.causalEventId).toBe(e2.causalEventId);
    });
});
