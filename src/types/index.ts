/**
 * Core types for Causal Behavioral Verification
 * @module types
 */

/**
 * Valid action types for causal events
 */
export type ActionType = 'request' | 'response' | 'error' | 'state_transition';

/**
 * Input for registering a new causal event
 */
export interface EventInput {
    /** ERC-8004 compliant agent address or identifier */
    agentId: string;
    /** Type of action being recorded */
    actionType: ActionType;
    /** SHA3-256 hash of the action payload (never raw payload) */
    payloadHash: string;
    /** Hash of immediately preceding causal event (null for root) */
    predecessorHash: string | null;
    /** Unix epoch timestamp (client-side, not trusted) */
    timestamp: number;
}

/**
 * Complete causal event record
 */
export interface CausalEvent extends EventInput {
    /** UUIDv7 identifier for this event */
    causalEventId: string;
    /** SHA3-256 hash of concatenated event fields */
    eventHash: string;
    /** Merkle tree leaf index (0-indexed) */
    positionInTree: number;
    /** Current Merkle tree root hash at time of registration */
    treeRootHash: string;
}

/**
 * Merkle proof path element
 */
export interface ProofPathElement {
    /** Hash of the current node */
    eventHash: string;
    /** Hash of the sibling node */
    siblingHash: string;
    /** Position of sibling relative to current node */
    position: 'left' | 'right';
}

/**
 * Complete causal proof structure
 */
export interface CausalProof {
    /** The event being proven */
    targetEvent: CausalEvent;
    /** Merkle inclusion proof path */
    proofPath: ProofPathElement[];
    /** Chain of preceding causal events */
    causalChain: CausalChainElement[];
    /** Tree root hash at proof generation time */
    treeRootHash: string;
    /** ECDSA signature over tree root by agent's private key */
    agentSignature: string;
}

/**
 * Simplified event representation for causal chain
 */
export interface CausalChainElement {
    /** Event hash */
    eventHash: string;
    /** Action type */
    actionType: ActionType;
    /** Timestamp */
    timestamp: number;
}

/**
 * Verification result from stateless verifier
 */
export interface VerificationResult {
    /** Overall validity */
    isValid: boolean;
    /** Error messages if invalid */
    errors: string[];
    /** Count of verified actions in chain */
    verifiedActions: number;
    /** Trust score 0.0-1.0 based on chain integrity */
    trustScore: number;
}

/**
 * Semantic rules for proof verification
 */
export interface SemanticRules {
    /** Require response to be preceded by request */
    requestMustPrecedeResponse?: boolean;
    /** Maximum time gap between events in milliseconds */
    maxTimeGapMs?: number;
    /** Required action types in the chain */
    requiredActionTypes?: ActionType[];
    /** Forbidden action types (e.g., 'error' for high-trust) */
    forbiddenActionTypes?: ActionType[];
}

/**
 * Exported tree structure for debugging
 */
export interface TreeExport {
    /** All leaf hashes in order */
    leaves: string[];
    /** All internal node hashes by level */
    levels: string[][];
    /** Current root hash */
    rootHash: string;
    /** Total number of leaves */
    leafCount: number;
}

/**
 * Registry export including events and tree
 */
export interface RegistryExport {
    /** All registered events */
    events: CausalEvent[];
    /** Merkle tree export */
    tree: TreeExport;
    /** Agent ID this registry belongs to */
    agentId: string;
}
