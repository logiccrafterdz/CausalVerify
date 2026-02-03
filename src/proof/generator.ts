/**
 * Proof Generator
 * Orchestrates the creation of atomic causal proofs
 * @module proof/generator
 */

import {
    CausalEvent,
    CausalProof,
    CausalChainElement,
    ProofPathElement
} from '../types/index.js';
import { CausalEventRegistry } from '../registry/registry.js';
import { sign } from '../crypto/ecdsa.js';

/**
 * Generates atomic causal proofs from a registry
 */
export class ProofGenerator {
    private registry: CausalEventRegistry;

    /**
     * @param registry - The event registry to generate proofs from
     */
    constructor(registry: CausalEventRegistry) {
        this.registry = registry;
    }

    /**
     * Generate a complete causal proof for an event
     * @param eventId - The ID of the event to prove
     * @param privateKey - Agent's private key for signing
     * @param chainDepth - How many preceding events to include (default: all)
     * @returns Complete signed causal proof
     * @throws Error if event not found or registration is incomplete
     */
    generateProof(eventId: string, privateKey: string, chainDepth?: number): CausalProof {
        const targetEvent = this.registry.getEvent(eventId);
        if (!targetEvent) {
            throw new Error(`Event ${eventId} not found in registry`);
        }

        // 1. Get Merkle inclusion path
        const proofPath = this.registry.getProofPath(eventId);
        if (!proofPath) {
            throw new Error(`Merkle proof path not found for event ${eventId}`);
        }

        // 2. Extract causal chain
        const causalChain = this.registry.getEventChain(eventId, chainDepth)
            .map(event => ({
                eventHash: event.eventHash,
                actionType: event.actionType,
                timestamp: event.timestamp,
                predecessorHash: event.predecessorHash
            }));

        // 3. Get current root hash and sign it
        const treeRootHash = this.registry.getRootHash();
        const agentSignature = sign(treeRootHash, privateKey);

        return {
            targetEvent,
            proofPath,
            causalChain,
            treeRootHash,
            agentSignature
        };
    }

    /**
     * Generate batch proofs for multiple events
     * @param eventIds - IDs of events to prove
     * @param privateKey - Agent's private key
     * @returns Array of signed causal proofs
     */
    generateBatchProofs(eventIds: string[], privateKey: string): CausalProof[] {
        return eventIds.map(id => this.generateProof(id, privateKey));
    }
}
