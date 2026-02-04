/**
 * Progressive Verification Tests
 */

import { describe, it, expect } from 'vitest';
import {
    CausalEventRegistry,
    ProofGenerator,
    generateKeyPair,
    sha3,
    ProgressiveVerifier
} from '../index.js';

describe('Progressive Verification', () => {
    it('should grant immediate trust for valid light proofs', async () => {
        const { privateKey } = generateKeyPair();
        const agentId = '0xAgent';
        const registry = new CausalEventRegistry(agentId);

        // Setup history
        for (let i = 0; i < 3; i++) {
            registry.registerEvent({
                agentId,
                actionType: 'request',
                payloadHash: sha3(i.toString()),
                predecessorHash: i === 0 ? null : registry.getLastEventHash(),
                timestamp: Date.now()
            });
        }

        const generator = new ProofGenerator(registry);
        const allEvents = registry.export().events;
        const lastEvent = allEvents[allEvents.length - 1]!;
        const lastId = lastEvent.causalEventId;
        const fullProof = generator.generateProof(lastId, privateKey);

        const lightProof = {
            agentId,
            targetEventHash: fullProof.targetEvent.eventHash,
            causalChain: fullProof.causalChain.map(el => ({ eventHash: el.eventHash, timestamp: el.timestamp })),
            timestamp: Date.now()
        };

        const verifier = new ProgressiveVerifier();

        const result = await verifier.verify({ light: lightProof, full: fullProof }, { agentId });

        expect(result.canProceed).toBe(true);
        expect(result.immediateTrust).toBe(0.7);
        expect(result.deferredStatus).toBe('not_requested'); // Since no publicKey provided
    });

    it('should handle high-value threshold by requiring full verification', async () => {
        const agentId = '0xAgent';
        const lightProof: any = {
            agentId,
            targetEventHash: '0x123',
            causalChain: [{ eventHash: '0x123', timestamp: Date.now() }],
            timestamp: Date.now()
        };

        const verifier = new ProgressiveVerifier();
        const result = await verifier.verify({ light: lightProof }, { agentId }, { isHighValue: true, minDepth: 1 });

        expect(result.canProceed).toBe(false);
        expect(result.reason).toBe('high_value_requires_full_verification');
    });

    it('should reject outdated light proofs', async () => {
        const agentId = '0xAgent';
        const lightProof: any = {
            agentId,
            targetEventHash: '0x123',
            causalChain: [{ eventHash: '0x123', timestamp: Date.now() - 1000000 }],
            timestamp: Date.now() - 1000000
        };

        const verifier = new ProgressiveVerifier();
        const result = await verifier.verify({ light: lightProof }, { agentId });

        expect(result.canProceed).toBe(false);
        expect(result.reason).toBe('light_verification_failed');
    });

    it('should reject light proofs with invalid temporal ordering', async () => {
        const agentId = '0xAgent';
        const lightProof: any = {
            agentId,
            targetEventHash: '0x124', // Target is last in chain
            causalChain: [
                { eventHash: '0x123', timestamp: 2000 },
                { eventHash: '0x124', timestamp: 1000 } // Out of order, but hash check passes
            ],
            timestamp: Date.now()
        };

        const verifier = new ProgressiveVerifier();
        const result = await verifier.verify({ light: lightProof }, { agentId }, { minDepth: 2 });
        expect(result.canProceed).toBe(false);
    });

    it('should reject light proofs where target is not the last element', async () => {
        const agentId = '0xAgent';
        const lightProof: any = {
            agentId,
            targetEventHash: '0x123',
            causalChain: [
                { eventHash: '0x123', timestamp: 1000 },
                { eventHash: '0x124', timestamp: 2000 }
            ],
            timestamp: Date.now()
        };

        const verifier = new ProgressiveVerifier();
        const result = await verifier.verify({ light: lightProof }, { agentId }, { minDepth: 2 });
        expect(result.canProceed).toBe(false);
    });

    it('should execute deferred verification when requested', async () => {
        const { privateKey, publicKey } = generateKeyPair();
        const agentId = '0xAgent';
        const registry = new CausalEventRegistry(agentId);
        const event = registry.registerEvent({ agentId, actionType: 'request', payloadHash: sha3('1'), predecessorHash: null, timestamp: Date.now() });
        const generator = new ProofGenerator(registry);
        const fullProof = generator.generateProof(event.causalEventId, privateKey);
        const lightProof = {
            agentId,
            targetEventHash: fullProof.targetEvent.eventHash,
            causalChain: fullProof.causalChain.map(el => ({ eventHash: el.eventHash, timestamp: el.timestamp })),
            timestamp: Date.now()
        };

        const verifier = new ProgressiveVerifier();
        const result = await verifier.verify({ light: lightProof, full: fullProof }, { agentId, publicKey }, { autoVerifyFull: true });

        expect(result.deferredStatus).toBe('pending');
        const fullRes = await result.fullResult;
        expect(fullRes?.isValid).toBe(true);
    });
});
