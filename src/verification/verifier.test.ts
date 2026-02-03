/**
 * Verifier and Rules Engine Tests
 */

import { describe, it, expect } from 'vitest';
import { verifyProof, verifyCausalChain } from './verifier.js';
import { SemanticRulesEngine } from './rules.js';
import { CausalEventRegistry } from '../registry/registry.js';
import { ProofGenerator } from '../proof/generator.js';
import { generateKeyPair, sha3 } from '../crypto/index.js';

describe('Stateless Verification', () => {
    const agentId = '0xAgent';
    const { privateKey, publicKey } = generateKeyPair();

    describe('verifyProof', () => {
        it('should verify a valid proof', () => {
            const registry = new CausalEventRegistry(agentId);
            const generator = new ProofGenerator(registry);

            const event = registry.registerEvent({
                agentId,
                actionType: 'request',
                payloadHash: sha3('p1'),
                predecessorHash: null,
                timestamp: Date.now()
            });

            const proof = generator.generateProof(event.causalEventId, privateKey);
            const result = verifyProof(proof, agentId, publicKey);

            expect(result.isValid).toBe(true);
            expect(result.errors.length).toBe(0);
            expect(result.verifiedActions).toBe(1);
        });

        it('should reject proof with wrong agentId', () => {
            const registry = new CausalEventRegistry(agentId);
            const generator = new ProofGenerator(registry);
            const event = registry.registerEvent({
                agentId,
                actionType: 'request',
                payloadHash: sha3('p1'),
                predecessorHash: null,
                timestamp: Date.now()
            });

            const proof = generator.generateProof(event.causalEventId, privateKey);
            const result = verifyProof(proof, 'WrongAgent', publicKey);

            expect(result.isValid).toBe(false);
            expect(result.errors).toContain('Agent ID mismatch: expected WrongAgent, got 0xAgent');
        });

        it('should reject proof with tampered root signature', () => {
            const registry = new CausalEventRegistry(agentId);
            const generator = new ProofGenerator(registry);
            const event = registry.registerEvent({
                agentId,
                actionType: 'request',
                payloadHash: sha3('p1'),
                predecessorHash: null,
                timestamp: Date.now()
            });

            const proof = generator.generateProof(event.causalEventId, privateKey);
            // Tamper with signature
            proof.agentSignature = proof.agentSignature.slice(0, -2) + '00';

            const result = verifyProof(proof, agentId, publicKey);
            expect(result.isValid).toBe(false);
            expect(result.errors).toContain('Agent signature verification failed');
        });

        it('should reject proof with tampered Merkle path', () => {
            const registry = new CausalEventRegistry(agentId);
            const generator = new ProofGenerator(registry);
            registry.registerEvent({
                agentId,
                actionType: 'request',
                payloadHash: sha3('p1'),
                predecessorHash: null,
                timestamp: Date.now()
            });

            const event = registry.registerEvent({
                agentId,
                actionType: 'response',
                payloadHash: sha3('p2'),
                predecessorHash: registry.getLastEventHash(),
                timestamp: Date.now()
            });

            const proof = generator.generateProof(event.causalEventId, privateKey);
            // Tamper with Merkle path
            proof.proofPath[0].siblingHash = sha3('tampered');

            const result = verifyProof(proof, agentId, publicKey);
            expect(result.isValid).toBe(false);
            expect(result.errors).toContain('Merkle inclusion proof verification failed');
        });
        it('should reject proof with tampered target event hash', () => {
            const registry = new CausalEventRegistry(agentId);
            const generator = new ProofGenerator(registry);
            const event = registry.registerEvent({
                agentId,
                actionType: 'request',
                payloadHash: sha3('p1'),
                predecessorHash: null,
                timestamp: Date.now()
            });

            const proof = generator.generateProof(event.causalEventId, privateKey);
            // Tamper with target event payload
            proof.targetEvent.payloadHash = sha3('tampered');

            const result = verifyProof(proof, agentId, publicKey);
            expect(result.isValid).toBe(false);
            expect(result.errors).toContain('Target event hash integrity check failed');
        });

        it('should verify Merkle inclusion directly', () => {
            const registry = new CausalEventRegistry(agentId);
            const event = registry.registerEvent({
                agentId,
                actionType: 'request',
                payloadHash: sha3('p1'),
                predecessorHash: null,
                timestamp: Date.now()
            });
            const proofPath = registry.getProofPath(event.causalEventId)!;
            const isIncluded = registry.verifyEventInclusion(event.eventHash);
            expect(isIncluded).toBe(true);
        });
    });

    describe('Causal Chain Verification', () => {
        it('should detect temporal anomalies', () => {
            const chain = [
                { eventHash: 'h1', actionType: 'request' as any, timestamp: 1000, predecessorHash: null },
                { eventHash: 'h2', actionType: 'response' as any, timestamp: 500, predecessorHash: 'h1' } // ERROR: backwards in time
            ];

            const result = verifyCausalChain(chain, 'h2');
            expect(result.valid).toBe(false);
            expect(result.errors[0]).toContain('Temporal anomaly');
        });

        it('should reject empty causal chain', () => {
            const result = verifyCausalChain([], 'h1');
            expect(result.valid).toBe(false);
            expect(result.errors).toContain('Causal chain is empty');
        });

        it('should reject chain with final hash mismatch', () => {
            const chain = [
                { eventHash: 'h1', actionType: 'request' as any, timestamp: 1000, predecessorHash: null }
            ];
            const result = verifyCausalChain(chain, 'wrong-hash');
            expect(result.valid).toBe(false);
            expect(result.errors[0]).toContain('Causal chain final hash mismatch');
        });
    });

    describe('SemanticRulesEngine', () => {
        it('should handle empty chain', () => {
            const engine = new SemanticRulesEngine({ requestMustPrecedeResponse: true });
            expect(engine.validate([]).valid).toBe(true);
        });

        it('should enforce request-before-response', () => {
            const engine = new SemanticRulesEngine({ requestMustPrecedeResponse: true });

            const validChain = [
                { eventHash: 'h1', actionType: 'request' as any, timestamp: 1000, predecessorHash: null },
                { eventHash: 'h2', actionType: 'response' as any, timestamp: 2000, predecessorHash: 'h1' }
            ];
            expect(engine.validate(validChain).valid).toBe(true);

            const invalidChain = [
                { eventHash: 'h2', actionType: 'response' as any, timestamp: 2000, predecessorHash: null }
            ];
            const result = engine.validate(invalidChain);
            expect(result.valid).toBe(false);
            expect(result.violations[0]).toContain('Protocol violation');
        });

        it('should enforce max time gap', () => {
            const engine = new SemanticRulesEngine({ maxTimeGapMs: 1000 });

            const chain = [
                { eventHash: 'h1', actionType: 'request' as any, timestamp: 1000, predecessorHash: null },
                { eventHash: 'h2', actionType: 'response' as any, timestamp: 3000, predecessorHash: 'h1' } // Gap of 2000ms
            ];

            const result = engine.validate(chain);
            expect(result.valid).toBe(false);
            expect(result.violations[0]).toContain('Temporal violation');
        });

        it('should enforce direct causality', () => {
            const engine = new SemanticRulesEngine({ requireDirectCausality: true });

            const validChain = [
                { eventHash: 'h1', actionType: 'request' as any, timestamp: 1000, predecessorHash: null },
                { eventHash: 'h2', actionType: 'response' as any, timestamp: 2000, predecessorHash: 'h1' }
            ];
            expect(engine.validate(validChain).valid).toBe(true);

            const invalidChain = [
                { eventHash: 'h1', actionType: 'request' as any, timestamp: 1000, predecessorHash: null },
                { eventHash: 'h3', actionType: 'response' as any, timestamp: 2000, predecessorHash: 'h2' } // ERROR: h3's predecessor is h2, not h1
            ];
            const result = engine.validate(invalidChain);
            expect(result.valid).toBe(false);
            expect(result.violations[0]).toContain('Causality violation');
        });

        it('should enforce minimum verification depth', () => {
            const engine = new SemanticRulesEngine({ minVerificationDepth: 3 });

            const shortChain = [
                { eventHash: 'h1', actionType: 'request' as any, timestamp: 1000, predecessorHash: null },
                { eventHash: 'h2', actionType: 'response' as any, timestamp: 2000, predecessorHash: 'h1' }
            ];

            const result = engine.validate(shortChain);
            expect(result.valid).toBe(false);
            expect(result.violations[0]).toContain('Insufficient chain depth');

            const longChain = [
                { eventHash: 'h0', actionType: 'request' as any, timestamp: 500, predecessorHash: null },
                { eventHash: 'h1', actionType: 'request' as any, timestamp: 1000, predecessorHash: 'h0' },
                { eventHash: 'h2', actionType: 'response' as any, timestamp: 2000, predecessorHash: 'h1' }
            ];
            expect(engine.validate(longChain).valid).toBe(true);
        });

        it('should enforce required and forbidden action types', () => {
            const engine = new SemanticRulesEngine({
                requiredActionTypes: ['request'],
                forbiddenActionTypes: ['error']
            });

            const chainWithForbidden = [
                { eventHash: 'h1', actionType: 'error' as any, timestamp: 1000, predecessorHash: null }
            ];
            const resultForbidden = engine.validate(chainWithForbidden);
            expect(resultForbidden.valid).toBe(false);
            expect(resultForbidden.violations).toContain('Forbidden action type detected: error in event h1');
            expect(resultForbidden.violations).toContain('Missing required action type: request');
        });
    });
});
