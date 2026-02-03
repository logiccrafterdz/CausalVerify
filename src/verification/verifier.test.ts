/**
 * Verifier and Rules Engine Tests
 */

import { describe, it, expect } from 'vitest';
import { verifyProof, verifyCausalChain, verifyMerkleInclusion } from './verifier.js';
import { verifyPrePayment, verifyPostPayment } from './patterns.js';
import { CausalEventRegistry } from '../registry/registry.js';
import { ProofGenerator } from '../proof/generator.js';
import { generateKeyPair, sha3 } from '../crypto/index.js';
import { CausalProof } from '../types/index.js';

describe('Stateless Verification', () => {
    const agentId = '0xAgent';
    const { privateKey, publicKey } = generateKeyPair();

    describe('verifyProof', () => {
        it('should verify a valid proof', () => {
            const registry = new CausalEventRegistry(agentId);
            const generator = new ProofGenerator(registry);
            const event = registry.registerEvent({ agentId, actionType: 'request', payloadHash: sha3('p1'), predecessorHash: null, timestamp: Date.now() });
            const proof = generator.generateProof(event.causalEventId, privateKey);
            const result = verifyProof(proof, agentId, publicKey);
            expect(result.isValid).toBe(true);
            expect(result.verifiedActions).toBe(1);
        });

        it('should reject proof with wrong agentId', () => {
            const registry = new CausalEventRegistry(agentId);
            const generator = new ProofGenerator(registry);
            const event = registry.registerEvent({ agentId, actionType: 'request', payloadHash: sha3('p1'), predecessorHash: null, timestamp: Date.now() });
            const proof = generator.generateProof(event.causalEventId, privateKey);
            const result = verifyProof(proof, 'WrongAgent', publicKey);
            expect(result.isValid).toBe(false);
            expect(result.errors).toContain('Agent ID mismatch: expected WrongAgent, got 0xAgent');
        });

        it('should reject proof with tampered root signature', () => {
            const registry = new CausalEventRegistry(agentId);
            const generator = new ProofGenerator(registry);
            const event = registry.registerEvent({ agentId, actionType: 'request', payloadHash: sha3('p1'), predecessorHash: null, timestamp: Date.now() });
            const proof = generator.generateProof(event.causalEventId, privateKey);
            proof.agentSignature = '0x' + '0'.repeat(128);
            const result = verifyProof(proof, agentId, publicKey);
            expect(result.isValid).toBe(false);
        });

        it('should reject proof with tampered Merkle path', () => {
            const registry = new CausalEventRegistry(agentId);
            const generator = new ProofGenerator(registry);
            registry.registerEvent({ agentId, actionType: 'request', payloadHash: sha3('p1'), predecessorHash: null, timestamp: Date.now() });
            const event = registry.registerEvent({ agentId, actionType: 'response', payloadHash: sha3('p2'), predecessorHash: registry.getLastEventHash(), timestamp: Date.now() });
            const proof = generator.generateProof(event.causalEventId, privateKey);
            proof.proofPath[0].siblingHash = sha3('tampered');
            const result = verifyProof(proof, agentId, publicKey);
            expect(result.isValid).toBe(false);
            expect(result.errors).toContain('Merkle inclusion proof verification failed');
        });

        it('should reject proof with empty causal chain', () => {
            const registry = new CausalEventRegistry(agentId);
            const generator = new ProofGenerator(registry);
            const event = registry.registerEvent({ agentId, actionType: 'request', payloadHash: sha3('p1'), predecessorHash: null, timestamp: Date.now() });
            const proof = generator.generateProof(event.causalEventId, privateKey);
            proof.causalChain = [];
            const result = verifyProof(proof, agentId, publicKey);
            expect(result.isValid).toBe(false);
            expect(result.errors).toContain('Causal chain is empty');
        });
    });

    describe('verifyCausalChain', () => {
        it('should detect mismatching final hash', () => {
            const chain = [{ eventHash: 'h1', actionType: 'request' as any, timestamp: 1000, predecessorHash: null }];
            const result = verifyCausalChain(chain, 'h2');
            expect(result.valid).toBe(false);
            expect(result.errors[0]).toContain('final hash mismatch');
        });

        it('should detect temporal anomaly', () => {
            const chain = [
                { eventHash: 'h1', actionType: 'request' as any, timestamp: 1000, predecessorHash: null },
                { eventHash: 'h2', actionType: 'response' as any, timestamp: 500, predecessorHash: 'h1' }
            ];
            const result = verifyCausalChain(chain, 'h2');
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.includes('Temporal anomaly'))).toBe(true);
        });

        it('should handle missing predecessor', () => {
            const chain = [{ eventHash: 'h2', actionType: 'response' as any, timestamp: 1000, predecessorHash: 'h1' }];
            const result = verifyCausalChain(chain, 'h2');
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.includes('Invalid root event'))).toBe(true);
        });

        it('should detect causal gap injection (mismatching predecessor)', () => {
            const chain = [
                { eventHash: 'h1', actionType: 'request' as any, timestamp: 1000, predecessorHash: null },
                { eventHash: 'h3', actionType: 'response' as any, timestamp: 2000, predecessorHash: 'h2' }
            ];
            const result = verifyCausalChain(chain, 'h3');
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.includes('Causal gap detected'))).toBe(true);
        });
    });

    describe('verifyMerkleInclusion', () => {
        it('should verify directly', () => {
            const registry = new CausalEventRegistry(agentId);
            const event = registry.registerEvent({ agentId, actionType: 'request', payloadHash: sha3('p1'), predecessorHash: null, timestamp: Date.now() });
            expect(verifyMerkleInclusion(event.eventHash, registry.getProofPath(event.causalEventId)!, registry.getRootHash())).toBe(true);
        });
    });

    describe('Patterns', () => {
        const createMockProof = (agentId: string): CausalProof => ({
            targetEvent: { causalEventId: 'id', agentId, eventHash: sha3('t'), actionType: 'request', payloadHash: sha3('p'), predecessorHash: null, timestamp: Date.now(), positionInTree: 0, treeRootHash: sha3('r') },
            proofPath: [],
            treeRootHash: sha3('r'),
            agentSignature: '0'.repeat(128),
            causalChain: [{ eventHash: sha3('t'), actionType: 'request', timestamp: Date.now(), predecessorHash: null }]
        });

        it('should handle pattern failures', () => {
            const { publicKey } = generateKeyPair();
            const proof = createMockProof('Wrong');
            expect(verifyPrePayment(proof, 'Right', publicKey).isValid).toBe(false);
            expect(verifyPostPayment(proof, 'Right', publicKey).isValid).toBe(false);
        });
    });
});
