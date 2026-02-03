/**
 * CausalVerify - Causal Behavioral Proofs Library
 * Trust layer for x402/ERC-8004 ecosystem
 * @module @causal-proofs/core
 */

// Core types
export type {
    ActionType,
    EventInput,
    CausalEvent,
    ProofPathElement,
    CausalProof,
    CausalChainElement,
    VerificationResult,
    SemanticRules,
    TreeExport,
    RegistryExport
} from './types/index.js';

// Crypto utilities
export { sha3, sha3Bytes, sha3Concat } from './crypto/sha3.js';
export { generateUUIDv7, extractTimestamp, isValidUUIDv7, compareUUIDv7 } from './crypto/uuid.js';

// Merkle tree
export { MerkleTree } from './merkle/tree.js';

// Event registry
export { CausalEventRegistry } from './registry/registry.js';
