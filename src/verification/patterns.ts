/**
 * Verification Patterns
 * High-level orchestration for common causal verification flows
 * @module verification/patterns
 */

import { CausalProof, VerificationResult, SemanticRules } from '../types/index.js';
import { verifyProof } from './verifier.js';
import { SemanticRulesEngine } from './rules.js';

/**
 * Verify a causal proof before processing a payment or request
 * Combines stateless verification with semantic rules
 * 
 * @param proof - The proof received in the X-Causal-Proof header
 * @param agentId - The expected agent identity
 * @param publicKey - The agent's public key
 * @param rules - Semantic rules to enforce (optional)
 * @returns Comprehensive verification result
 */
export function verifyPrePayment(
    proof: CausalProof,
    agentId: string,
    publicKey: string,
    rules?: SemanticRules
): VerificationResult {
    // 1. Basic Stateless Verification (Merkle + Signature + Integrity)
    const result = verifyProof(proof, agentId, publicKey);

    if (!result.isValid) {
        return result;
    }

    // 2. Semantic Rules Validation (Business Logic)
    if (rules) {
        const engine = new SemanticRulesEngine(rules);
        const semanticResult = engine.validate(proof.causalChain);

        if (!semanticResult.valid) {
            return {
                isValid: false,
                errors: [...result.errors, ...semanticResult.violations],
                verifiedActions: result.verifiedActions,
                trustScore: 0.5 // Partial trust if crypto is good but semantics fail
            };
        }
    }

    return result;
}

/**
 * Verify a causal proof for a completed transaction (Post-Settlement)
 */
export function verifyPostPayment(
    proof: CausalProof,
    agentId: string,
    publicKey: string,
    rules?: SemanticRules
): VerificationResult {
    // For now, post-payment follows the same logic, but could include 
    // additional checks like settlement confirmation in the future.
    return verifyPrePayment(proof, agentId, publicKey, rules);
}
