/**
 * Semantic Rules Engine
 * Implements business rules for verifying causal chains
 * @module verification/rules
 */

import { SemanticRules, CausalChainElement, ActionType } from '../types/index.js';

/**
 * Validates causal chains against semantic rules
 */
export class SemanticRulesEngine {
    private rules: SemanticRules;

    /**
     * @param rules - Configuration for semantic rules
     */
    constructor(rules: SemanticRules) {
        this.rules = rules;
    }

    /**
     * Validate a causal chain against the configured rules
     * @param chain - The causal chain to validate
     * @returns Validity and list of violations
     */
    validate(chain: CausalChainElement[]): { valid: boolean; violations: string[] } {
        const violations: string[] = [];

        if (chain.length === 0) {
            return { valid: true, violations: [] };
        }

        // 1. Request must precede response
        if (this.rules.requestMustPrecedeResponse) {
            for (let i = 0; i < chain.length; i++) {
                const current = chain[i];
                if (current && current.actionType === 'response') {
                    // Look for a preceding request either in the registry or the included chain
                    // Here we only check the provided chain
                    const slice = chain.slice(0, i);
                    const hasRequest = slice.some(e => e.actionType === 'request');
                    if (!hasRequest) {
                        violations.push(`Protocol violation: event ${current.eventHash} (response) has no preceding request in the chain`);
                    }
                }
            }
        }

        // 2. Max time gap
        if (this.rules.maxTimeGapMs) {
            for (let i = 1; i < chain.length; i++) {
                const current = chain[i];
                const previous = chain[i - 1];
                if (current && previous) {
                    const gap = current.timestamp - previous.timestamp;
                    if (gap > (this.rules.maxTimeGapMs!)) {
                        violations.push(`Temporal violation: gap between ${previous.eventHash} and ${current.eventHash} is ${gap}ms, exceeding max of ${this.rules.maxTimeGapMs}ms`);
                    }
                }
            }
        }

        // 3. Required action types
        if (this.rules.requiredActionTypes && this.rules.requiredActionTypes.length > 0) {
            const typesInChain = new Set(chain.map(e => e.actionType));
            for (const requiredType of this.rules.requiredActionTypes) {
                if (!typesInChain.has(requiredType)) {
                    violations.push(`Missing required action type: ${requiredType}`);
                }
            }
        }

        // 4. Forbidden action types
        if (this.rules.forbiddenActionTypes && this.rules.forbiddenActionTypes.length > 0) {
            for (const event of chain) {
                if (this.rules.forbiddenActionTypes.includes(event.actionType)) {
                    violations.push(`Forbidden action type detected: ${event.actionType} in event ${event.eventHash}`);
                }
            }
        }

        // 5. Direct Causality
        if (this.rules.requireDirectCausality) {
            for (let i = 1; i < chain.length; i++) {
                const current = chain[i];
                const previous = chain[i - 1];
                if (current && previous && current.predecessorHash !== previous.eventHash) {
                    violations.push(`Causality violation: event ${current.eventHash} is not a direct successor of ${previous.eventHash}`);
                }
            }
        }

        // 6. Minimum Verification Depth
        if (this.rules.minVerificationDepth && chain.length < this.rules.minVerificationDepth) {
            violations.push(`Insufficient chain depth: expected at least ${this.rules.minVerificationDepth}, got ${chain.length}`);
        }

        return {
            valid: violations.length === 0,
            violations
        };
    }
}
