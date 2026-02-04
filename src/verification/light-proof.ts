/**
 * Lightweight Verification Layer
 * Immediate trust based on metadata and hash matching (<5ms)
 * @module verification/light-proof
 */

import { LightProof } from '../types/index.js';

const DEFAULT_MAX_AGE_MS = 300000; // 5 minutes
const DEFAULT_MIN_DEPTH = 3;

/**
 * Verify a lightweight proof for immediate trust
 * @param proof - The light proof to verify
 * @param expectedAgentId - The expected agent ID
 * @param options - Minimum depth and maximum age
 * @returns boolean indicating if the proof meets immediate trust criteria
 */
export function verifyLightProof(
    proof: LightProof,
    expectedAgentId: string,
    options: { maxAgeMs?: number; minDepth?: number } = {}
): boolean {
    const maxAge = options.maxAgeMs ?? DEFAULT_MAX_AGE_MS;
    const minDepth = options.minDepth ?? DEFAULT_MIN_DEPTH;

    // 1. Basic Agent Check
    if (proof.agentId !== expectedAgentId) return false;

    // 2. Freshness Check
    const now = Date.now();
    if (now - proof.timestamp > maxAge) return false;

    // 3. Chain Length/Minimum Trust Depth
    if (proof.causalChain.length < minDepth) return false;

    // 4. Target Inclusion in Chain
    const targetInChain = proof.causalChain.some(el => el.eventHash === proof.targetEventHash);
    if (!targetInChain) return false;

    // 5. Chain Continuity (Hash Matching) - Lightweight version
    const lastElement = proof.causalChain[proof.causalChain.length - 1];
    if (lastElement?.eventHash !== proof.targetEventHash) return false;

    // 6. Basic Temporal Ordering
    for (let i = 1; i < proof.causalChain.length; i++) {
        if (proof.causalChain[i]!.timestamp < proof.causalChain[i - 1]!.timestamp) {
            return false;
        }
    }

    return true;
}
