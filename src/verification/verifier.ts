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

    // Simple trust score calculation: 1.0 if valid, 0.0 if not
    // In Week 3/4 this can be more nuanced based on chain length and rules
    const trustScore = isValid ? 1.0 : 0.0;

    return {
        isValid,
        errors,
        verifiedActions,
        trustScore
    };
}

/**
 * Verify the integrity and ordering of a causal chain
 * @param chain - The chain of events (oldest first)
 * @param expectedFinalHash - The hash that the chain should end with
 * @returns Object with validity and any errors
 */
export function verifyCausalChain(
    chain: CausalChainElement[],
    expectedFinalHash: string
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

    // In a stateless verifier, we can't fully "re-verify" the hashes of predecessors 
    // unless the chain includes enough data.
    // However, we can verify temporal ordering and structural integrity.
    for (let i = 0; i < chain.length; i++) {
        const current = chain[i];
        if (!current) continue;

        // Verify root node has no predecessor
        if (i === 0 && current.predecessorHash !== null) {
            errors.push('Invalid root event: first event in chain must have null predecessorHash');
        }

        // Verify sequential continuity
        if (i > 0) {
            const previous = chain[i - 1];
            if (previous) {
                if (current.predecessorHash !== previous.eventHash) {
                    errors.push(`Causal gap detected: event ${current.eventHash} at index ${i} expects predecessor ${current.predecessorHash}, but got ${previous.eventHash}`);
                }
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
