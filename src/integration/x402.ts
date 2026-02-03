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
 * Encode a CausalProof to a Base64 string for HTTP headers
 * @param proof - The proof to encode
 * @returns Base64 encoded JSON string
 */
export function encodeCausalHeader(proof: CausalProof): string {
    const json = JSON.stringify(proof);
    return Buffer.from(json).toString('base64');
}

/**
 * Decode a CausalProof from a Base64 header string
 * @param headerValue - The Base64 string from an HTTP header
 * @returns Decoded CausalProof object
 * @throws Error if decoding or parsing fails
 */
export function decodeCausalHeader(headerValue: string): CausalProof {
    try {
        const json = Buffer.from(headerValue, 'base64').toString('utf8');
        return JSON.parse(json) as CausalProof;
    } catch (error) {
        throw new Error('Failed to decode X-Causal-Proof header: Invalid format or encoding');
    }
}

/**
 * Utility to create metadata for an x402 payment request
 * @param proof - The causal proof to include
 * @returns Object formatted for x402 metadata
 */
export function createPaymentRequestMetadata(proof: CausalProof): Record<string, any> {
    return {
        causalProof: proof,
        version: '1.0.0'
    };
}
