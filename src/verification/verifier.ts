/**
 * Stateless Verifier
 * Pure functions for verifying causal proofs without internal state
 * @module verification/verifier
 */

import {
    CausalProof,
    VerificationResult,
    ProofPathElement,
    CausalChainElement
} from '../types/index.js';
import { verify as verifySignature } from '../crypto/ecdsa.js';
import { MerkleTree } from '../merkle/tree.js';
import { sha3Concat } from '../crypto/sha3.js';

/**
 * Verify a complete causal proof
 * @param proof - The proof to verify
 * @param expectedAgentId - The agent ID that should have signed the proof
 * @param expectedPublicKey - The public key corresponding to the agent ID
 * @returns Verification result with details
 */
export function verifyProof(
    proof: CausalProof,
    expectedAgentId: string,
    expectedPublicKey: string
): VerificationResult {
    const errors: string[] = [];
    let verifiedActions = 0;

    // 1. Verify Agent Identity
    if (proof.targetEvent.agentId !== expectedAgentId) {
        errors.push(`Agent ID mismatch: expected ${expectedAgentId}, got ${proof.targetEvent.agentId}`);
    }

    // 2. Verify Merkle Inclusion Proof
    const isIncluded = MerkleTree.verifyProof(
        proof.targetEvent.eventHash,
        proof.proofPath,
        proof.treeRootHash
    );
    if (!isIncluded) {
        errors.push('Merkle inclusion proof verification failed');
    }

    // 3. Verify Agent Signature
    const isSignatureValid = verifySignature(
        proof.treeRootHash,
        proof.agentSignature,
        expectedPublicKey
    );
    if (!isSignatureValid) {
        errors.push('Agent signature verification failed');
    }

    // 4. Verify target event hash matches its content
    const computedEventHash = sha3Concat(
        proof.targetEvent.agentId,
        proof.targetEvent.actionType,
        proof.targetEvent.payloadHash,
        proof.targetEvent.predecessorHash,
        String(proof.targetEvent.timestamp)
    );
    if (computedEventHash !== proof.targetEvent.eventHash) {
        errors.push('Target event hash integrity check failed');
    }

    // 5. Verify Causal Chain Integrity
    const chainVerification = verifyCausalChain(proof.causalChain, proof.targetEvent.eventHash);
    if (!chainVerification.valid) {
        errors.push(...chainVerification.errors);
    } else {
        verifiedActions = proof.causalChain.length;
    }

    const isValid = errors.length === 0;

    // HIGH-003: Granular trust scoring based on multiple factors
    // Trust is calculated from:
    // - Base cryptographic validity: 0.2
    // - Chain length bonus: up to 0.4 (max at 10+ events)
    // - Recency bonus: up to 0.4 (decays over 5 minutes)
    const trustScore = isValid ? calculateTrustScore(proof.causalChain, proof.targetEvent.timestamp) : 0.0;

    return {
        isValid,
        errors,
        verifiedActions,
        trustScore
    };
}

/**
 * Calculate granular trust score based on chain characteristics
 * @param chain - The verified causal chain
 * @param eventTimestamp - Timestamp of the target event
 * @returns Trust score between 0.0 and 1.0
 */
function calculateTrustScore(chain: CausalChainElement[], eventTimestamp: number): number {
    const BASE_SCORE = 0.2; // Cryptographic validity baseline
    const MAX_LENGTH_BONUS = 0.4;
    const MAX_RECENCY_BONUS = 0.4;
    const OPTIMAL_CHAIN_LENGTH = 10;
    const FRESHNESS_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

    // Chain length bonus: longer verified chains = higher trust
    const lengthRatio = Math.min(chain.length / OPTIMAL_CHAIN_LENGTH, 1.0);
    const lengthBonus = lengthRatio * MAX_LENGTH_BONUS;

    // Recency bonus: recent events = higher trust
    const age = Date.now() - eventTimestamp;
    const recencyRatio = Math.max(0, 1 - (age / FRESHNESS_WINDOW_MS));
    const recencyBonus = recencyRatio * MAX_RECENCY_BONUS;

    return Math.min(BASE_SCORE + lengthBonus + recencyBonus, 1.0);
}

/**
 * Verify the integrity and ordering of a causal chain
 * 
 * IMPORTANT: This is a stateless verifier that validates structural integrity
 * (predecessor linkage and temporal ordering) but cannot re-compute event hashes
 * without full event data. For complete verification, ensure each chain element
 * is also validated via Merkle inclusion proof.
 * 
 * @param chain - The chain of events (oldest first)
 * @param expectedFinalHash - The hash that the chain should end with
 * @param options - Verification options
 * @returns Object with validity and any errors
 */
export function verifyCausalChain(
    chain: CausalChainElement[],
    expectedFinalHash: string,
    options: { requireNullRoot?: boolean } = {}
): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (chain.length === 0) {
        return { valid: false, errors: ['Causal chain is empty'] };
    }

    // The last element in the chain MUST match the expected final hash
    const lastElement = chain[chain.length - 1];
    if (!lastElement || lastElement.eventHash !== expectedFinalHash) {
        errors.push(`Causal chain final hash mismatch: expected ${expectedFinalHash}, got ${lastElement?.eventHash ?? 'none'}`);
    }

    // Verify structural integrity and temporal ordering
    for (let i = 0; i < chain.length; i++) {
        const current = chain[i]!;

        // CRIT-003 FIX: Only enforce null predecessor if explicitly requested
        // (for complete chains from the beginning of an agent's history)
        // Truncated chains may have a non-null predecessor on the first element
        if (i === 0 && options.requireNullRoot && current.predecessorHash !== null) {
            errors.push('Invalid root event: first event in complete chain must have null predecessorHash');
        }

        // Verify sequential continuity between adjacent elements
        if (i > 0) {
            const previous = chain[i - 1];
            if (previous) {
                // Each element must reference the previous as its predecessor
                if (current.predecessorHash !== previous.eventHash) {
                    errors.push(`Causal gap detected: event ${current.eventHash} at index ${i} expects predecessor ${current.predecessorHash}, but got ${previous.eventHash}`);
                }
                // Temporal ordering: events must not be before their predecessors
                if (current.timestamp < previous.timestamp) {
                    errors.push(`Temporal anomaly at index ${i}: event ${current.eventHash} happened before its predecessor`);
                }
            }
        }
    }

    return {
        valid: errors.length === 0,
        errors
    };
}

/**
 * Verify Merkle inclusion for a single hash
 * @param hash - Hash to verify
 * @param proofPath - Merkle proof path
 * @param rootHash - Expected root hash
 * @returns True if included
 */
export function verifyMerkleInclusion(
    hash: string,
    proofPath: ProofPathElement[],
    rootHash: string
): boolean {
    return MerkleTree.verifyProof(hash, proofPath, rootHash);
}
