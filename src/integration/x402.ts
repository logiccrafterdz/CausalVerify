/**
 * x402 Integration Layer
 * Utilities for bridging CausalVerify with the x402 protocol (ERC-8004)
 * @module integration/x402
 */

import { CausalProof } from '../types/index.js';

/**
 * Standard header name for causal proofs in x402
 */
export const CAUSAL_PROOF_HEADER = 'X-Causal-Proof';

/**
 * Schema version header for protocol negotiation
 */
export const CAUSAL_PROOF_SCHEMA_HEADER = 'X-Causal-Proof-Schema';

/**
 * Current schema version
 */
export const CAUSAL_PROOF_SCHEMA_VERSION = 'causal-v1';

/**
 * Encode a CausalProof to a Base64 string for HTTP headers
 * Uses browser-compatible encoding (no Node.js Buffer dependency)
 * @param proof - The proof to encode
 * @returns Base64 encoded JSON string
 */
export function encodeCausalHeader(proof: CausalProof): string {
    const json = JSON.stringify(proof);
    // Browser-compatible: TextEncoder + btoa with Unicode handling
    const bytes = new TextEncoder().encode(json);
    const binString = Array.from(bytes, (byte) => String.fromCodePoint(byte)).join('');
    return btoa(binString);
}

/**
 * Decode a CausalProof from a Base64 header string
 * Uses browser-compatible decoding with schema validation
 * @param headerValue - The Base64 string from an HTTP header
 * @returns Decoded CausalProof object
 * @throws Error if decoding, parsing, or validation fails
 */
export function decodeCausalHeader(headerValue: string): CausalProof {
    try {
        // Browser-compatible: atob + TextDecoder with Unicode handling
        const binString = atob(headerValue);
        const bytes = Uint8Array.from(binString, (char) => char.codePointAt(0)!);
        const json = new TextDecoder().decode(bytes);
        const parsed = JSON.parse(json);

        // HIGH-002: Schema validation to prevent type confusion attacks
        if (!isValidCausalProof(parsed)) {
            throw new Error('Invalid CausalProof structure');
        }

        return parsed as CausalProof;
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        throw new Error(`Failed to decode X-Causal-Proof header: ${message}`);
    }
}

/**
 * Validate that an object has the required CausalProof structure
 * @param obj - Object to validate
 * @returns True if the object matches CausalProof schema
 */
export function isValidCausalProof(obj: unknown): obj is CausalProof {
    if (obj === null || typeof obj !== 'object') return false;

    const proof = obj as Record<string, unknown>;

    // Required top-level fields
    if (!proof.targetEvent || typeof proof.targetEvent !== 'object') return false;
    if (!Array.isArray(proof.proofPath)) return false;
    if (!Array.isArray(proof.causalChain)) return false;
    if (typeof proof.treeRootHash !== 'string') return false;
    if (typeof proof.agentSignature !== 'string') return false;

    // Validate targetEvent structure
    const event = proof.targetEvent as Record<string, unknown>;
    if (typeof event.causalEventId !== 'string') return false;
    if (typeof event.agentId !== 'string') return false;
    if (typeof event.eventHash !== 'string') return false;
    if (typeof event.actionType !== 'string') return false;
    if (typeof event.payloadHash !== 'string') return false;
    if (typeof event.timestamp !== 'number') return false;
    if (typeof event.positionInTree !== 'number') return false;
    if (typeof event.treeRootHash !== 'string') return false;

    return true;
}

/**
 * Utility to create metadata for an x402 payment request
 * @param proof - The causal proof to include
 * @returns Object formatted for x402 metadata
 */
export function createPaymentRequestMetadata(proof: CausalProof): Record<string, unknown> {
    return {
        causalProof: proof,
        version: CAUSAL_PROOF_SCHEMA_VERSION
    };
}

