/**
 * Causal Event Registry
 * Manages registration and retrieval of causally-ordered events
 * @module registry
 */

import { sha3Concat } from '../crypto/sha3.js';
import { generateUUIDv7 } from '../crypto/uuid.js';
import { MerkleTree } from '../merkle/tree.js';
import type {
    EventInput,
    CausalEvent,
    RegistryExport,
    ProofPathElement
} from '../types/index.js';

/**
 * Registry for causally-ordered events with Merkle tree backing
 */
export class CausalEventRegistry {
    private readonly agentId: string;
    private readonly events: Map<string, CausalEvent> = new Map();
    private readonly eventsByHash: Map<string, CausalEvent> = new Map();
    private readonly tree: MerkleTree;
    private lastEventHash: string | null = null;

    /**
     * Create a new registry for an agent
     * @param agentId - ERC-8004 compliant agent identifier
     */
    constructor(agentId: string) {
        if (!agentId || agentId.trim() === '') {
            throw new Error('agentId is required and cannot be empty');
        }
        this.agentId = agentId;
        this.tree = new MerkleTree();
    }

    /**
     * Register a new causal event
     * @param input - Event input parameters
     * @returns Complete causal event record
     * @throws Error if predecessor hash is invalid
     */
    registerEvent(input: EventInput): CausalEvent {
        // Validate agent ID matches registry
        if (input.agentId !== this.agentId) {
            throw new Error(
                `Agent ID mismatch: expected ${this.agentId}, got ${input.agentId}`
            );
        }

        // Validate predecessor hash
        if (input.predecessorHash !== null) {
            if (!this.eventsByHash.has(input.predecessorHash)) {
                throw new Error(
                    `Invalid predecessor hash: ${input.predecessorHash} not found in registry`
                );
            }
        } else if (this.events.size > 0) {
            // First event can have null predecessor, subsequent cannot
            // unless explicitly breaking causality (not recommended)
        }

        // Validate action type
        const validActionTypes = ['request', 'response', 'error', 'state_transition'];
        if (!validActionTypes.includes(input.actionType)) {
            throw new Error(`Invalid action type: ${input.actionType}`);
        }

        // Generate event ID
        const causalEventId = generateUUIDv7();

        // Compute event hash
        const eventHash = sha3Concat(
            input.agentId,
            input.actionType,
            input.payloadHash,
            input.predecessorHash,
            String(input.timestamp)
        );

        // Get position in tree
        const positionInTree = this.tree.getLeafCount();

        // Append to Merkle tree and get new root
        const treeRootHash = this.tree.append(eventHash);

        // Create complete event
        const event: CausalEvent = {
            ...input,
            causalEventId,
            eventHash,
            positionInTree,
            treeRootHash
        };

        // Store event
        this.events.set(causalEventId, event);
        this.eventsByHash.set(eventHash, event);
        this.lastEventHash = eventHash;

        return event;
    }

    /**
     * Get an event by its causal event ID
     * @param causalEventId - UUIDv7 event identifier
     * @returns Event or null if not found
     */
    getEvent(causalEventId: string): CausalEvent | null {
        return this.events.get(causalEventId) ?? null;
    }

    /**
     * Get an event by its hash
     * @param eventHash - SHA3-256 event hash
     * @returns Event or null if not found
     */
    getEventByHash(eventHash: string): CausalEvent | null {
        return this.eventsByHash.get(eventHash) ?? null;
    }

    /**
     * Get causal chain leading to an event
     * @param eventId - Target event ID
     * @param depth - Maximum number of predecessors to include
     * @returns Array of events in causal order (oldest first)
     */
    getEventChain(eventId: string, depth: number = 5): CausalEvent[] {
        const targetEvent = this.events.get(eventId);
        if (!targetEvent) {
            return [];
        }

        const chain: CausalEvent[] = [];
        let currentHash: string | null = targetEvent.predecessorHash;

        // Walk backwards through causal chain
        while (currentHash !== null && chain.length < depth) {
            const event = this.eventsByHash.get(currentHash);
            if (!event) {
                break; // Chain broken (should not happen in valid registry)
            }
            chain.unshift(event); // Add at beginning to maintain order
            currentHash = event.predecessorHash;
        }

        // Add target event at end
        chain.push(targetEvent);

        return chain;
    }

    /**
     * Get Merkle proof path for an event
     * @param eventId - Event ID to get proof for
     * @returns Proof path or null if event not found
     */
    getProofPath(eventId: string): ProofPathElement[] | null {
        const event = this.events.get(eventId);
        if (!event) {
            return null;
        }
        return this.tree.getProofPath(event.positionInTree);
    }

    /**
     * Get the current Merkle tree root hash
     * @returns Current root hash or empty string if no events
     */
    getRootHash(): string {
        return this.tree.getRootHash();
    }

    /**
     * Get the last registered event hash
     * @returns Hash of most recent event or null if empty
     */
    getLastEventHash(): string | null {
        return this.lastEventHash;
    }

    /**
     * Get total number of events in registry
     */
    getEventCount(): number {
        return this.events.size;
    }

    /**
     * Get the agent ID for this registry
     */
    getAgentId(): string {
        return this.agentId;
    }

    /**
     * Export complete registry for debugging/inspection
     * @returns Full registry export
     */
    export(): RegistryExport {
        // Sort events by position for consistent ordering
        const sortedEvents = Array.from(this.events.values())
            .sort((a, b) => a.positionInTree - b.positionInTree);

        return {
            events: sortedEvents,
            tree: this.tree.export(),
            agentId: this.agentId
        };
    }

    /**
     * Verify that an event hash exists and matches Merkle inclusion
     * @param eventHash - Hash to verify
     * @returns True if event exists and is included in tree
     */
    verifyEventInclusion(eventHash: string): boolean {
        const event = this.eventsByHash.get(eventHash);
        if (!event) {
            return false;
        }

        const proofPath = this.tree.getProofPath(event.positionInTree);
        return MerkleTree.verifyProof(
            eventHash,
            proofPath,
            this.tree.getRootHash()
        );
    }
}
