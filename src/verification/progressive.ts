/**
 * Progressive Trust Orchestration
 * Orchestrates immediate (light) and deferred (full) verification
 * @module verification/progressive
 */

import {
    LightProof,
    CausalProof,
    ProgressiveResult,
    VerificationResult
} from '../types/index.js';
import { verifyProof } from './verifier.js';
import { verifyLightProof } from './light-proof.js';

export interface ProgressiveOptions {
    /** Whether to automatically trigger full verification in the background */
    autoVerifyFull?: boolean;
    /** Value threshold: if true, will NOT allow immediate trust for high-value transactions */
    isHighValue?: boolean;
    /** Minimum depth for light trust */
    minDepth?: number;
    /** Max age for light trust */
    maxAgeMs?: number;
}

/**
 * Orchestrates progressive verification of causal proofs
 */
export class ProgressiveVerifier {
    /**
     * Perform progressive verification
     * @param proofPackage - Contains light proof and optional full proof
     * @param context - Verification context (agent, keys, rules)
     * @param options - Progressive options
     */
    async verify(
        proofPackage: { light: LightProof; full?: CausalProof },
        context: { agentId: string; publicKey?: string },
        options: ProgressiveOptions = {}
    ): Promise<ProgressiveResult> {
        const { light, full } = proofPackage;
        const autoVerifyFull = options.autoVerifyFull ?? true;
        const isHighValue = options.isHighValue ?? false;

        // 1. Immediate Light Verification
        const immediateValid = verifyLightProof(light, context.agentId, {
            minDepth: options.minDepth,
            maxAgeMs: options.maxAgeMs
        });

        const canProceedImmediately = immediateValid && !isHighValue;

        // 2. Setup Deferred Full Verification
        let fullResult: Promise<VerificationResult> | undefined;
        let deferredStatus: 'pending' | 'completed' | 'not_requested' = 'not_requested';

        if (full && context.publicKey && autoVerifyFull) {
            deferredStatus = 'pending';
            // Offload to next event loop tick to ensure immediate return is truly fast
            fullResult = new Promise((resolve) => {
                setTimeout(() => {
                    const result = verifyProof(full!, context.agentId, context.publicKey!);
                    resolve(result);
                }, 0);
            });
        }

        return {
            canProceed: canProceedImmediately,
            reason: immediateValid
                ? (isHighValue ? 'high_value_requires_full_verification' : 'immediate_trust_granted')
                : 'light_verification_failed',
            immediateTrust: immediateValid ? 0.7 : 0.0, // Baseline trust for light proof
            deferredStatus,
            fullResult
        };
    }
}
