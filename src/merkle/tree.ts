/**
 * Append-Only Merkle Tree Implementation
 * Optimized for causal event ordering with proof generation
 * Uses O(log n) append algorithm
 * @module merkle/tree
 */

import { sha3Concat } from '../crypto/sha3.js';
import type { TreeExport, ProofPathElement } from '../types/index.js';

/**
 * Append-only Merkle tree for causal event hashes
 * Uses optimized incremental root computation
 */
export class MerkleTree {
    private leaves: string[] = [];
    private nodes: Map<string, string> = new Map(); // key: "level:index" -> hash

    /**
     * Create a new Merkle tree
     * @param initialLeaves - Optional initial leaf hashes
     */
    constructor(initialLeaves?: string[]) {
        if (initialLeaves && initialLeaves.length > 0) {
            for (const leaf of initialLeaves) {
                this.append(leaf);
            }
        }
    }

    /**
     * Append a new leaf hash and compute only necessary nodes
     * Uses O(log n) algorithm - only updates the path to root
     * @param leafHash - Hash to add as new leaf
     * @returns New root hash
     */
    append(leafHash: string): string {
        const leafIndex = this.leaves.length;
        this.leaves.push(leafHash);

        // Store the leaf node
        this.nodes.set(`0:${leafIndex}`, leafHash);

        // Compute path to root - only O(log n) hash computations
        let currentIndex = leafIndex;
        let currentLevel = 0;
        let currentHash = leafHash;

        while (true) {
            const parentIndex = Math.floor(currentIndex / 2);
            const isLeft = currentIndex % 2 === 0;

            if (isLeft) {
                // We're left child - no sibling yet (or sibling was removed)
                // Just promote up, root computation happens when sibling arrives
                this.nodes.set(`${currentLevel + 1}:${parentIndex}`, currentHash);
            } else {
                // We're right child - there must be a left sibling
                const siblingKey = `${currentLevel}:${currentIndex - 1}`;
                const siblingHash = this.nodes.get(siblingKey);

                if (siblingHash) {
                    currentHash = this.hashPair(siblingHash, currentHash);
                    this.nodes.set(`${currentLevel + 1}:${parentIndex}`, currentHash);
                }
            }

            // Check if we're at the top
            const nodesAtLevel = this.countNodesAtLevel(currentLevel + 1);
            if (nodesAtLevel <= 1) {
                break;
            }

            currentIndex = parentIndex;
            currentLevel++;
        }

        return this.getRootHash();
    }

    /**
     * Count nodes at a given level based on leaf count
     */
    private countNodesAtLevel(level: number): number {
        let count = this.leaves.length;
        for (let l = 0; l < level; l++) {
            count = Math.ceil(count / 2);
        }
        return count;
    }

    /**
     * Get tree height
     */
    private getHeight(): number {
        if (this.leaves.length === 0) return 0;
        if (this.leaves.length === 1) return 1;
        return Math.ceil(Math.log2(this.leaves.length)) + 1;
    }

    /**
     * Hash two nodes together (sorted ordering for consistency)
     */
    private hashPair(left: string, right: string): string {
        if (left <= right) {
            return sha3Concat(left, right);
        }
        return sha3Concat(right, left);
    }

    /**
     * Get the current root hash
     * @returns Root hash or empty string if tree is empty
     */
    getRootHash(): string {
        if (this.leaves.length === 0) return '';
        if (this.leaves.length === 1) return this.leaves[0] ?? '';

        // Find root node at top level
        const height = this.getHeight();
        for (let level = height - 1; level >= 0; level--) {
            const key = `${level}:0`;
            const hash = this.nodes.get(key);
            if (hash && this.countNodesAtLevel(level) === 1) {
                return hash;
            }
        }

        return this.nodes.get('0:0') ?? '';
    }

    /**
     * Get the number of leaves in the tree
     */
    getLeafCount(): number {
        return this.leaves.length;
    }

    /**
     * Generate Merkle proof path for a leaf at given index
     * @param leafIndex - Index of the leaf to prove
     * @returns Array of proof path elements
     * @throws Error if index is out of bounds
     */
    getProofPath(leafIndex: number): ProofPathElement[] {
        if (leafIndex < 0 || leafIndex >= this.leaves.length) {
            throw new Error(`Leaf index ${leafIndex} out of bounds (0-${this.leaves.length - 1})`);
        }

        const proofPath: ProofPathElement[] = [];
        let currentIndex = leafIndex;
        const height = this.getHeight();

        for (let level = 0; level < height - 1; level++) {
            const isLeftNode = currentIndex % 2 === 0;
            const siblingIndex = isLeftNode ? currentIndex + 1 : currentIndex - 1;

            const currentKey = `${level}:${currentIndex}`;
            const siblingKey = `${level}:${siblingIndex}`;

            const currentHash = this.nodes.get(currentKey) ?? '';
            const siblingHash = this.nodes.get(siblingKey);

            if (siblingHash !== undefined) {
                proofPath.push({
                    eventHash: currentHash,
                    siblingHash: siblingHash,
                    position: isLeftNode ? 'right' : 'left'
                });
            } else {
                // No sibling (odd node count), self-paired
                proofPath.push({
                    eventHash: currentHash,
                    siblingHash: currentHash,
                    position: 'right'
                });
            }

            currentIndex = Math.floor(currentIndex / 2);
        }

        return proofPath;
    }

    /**
     * Verify a proof path leads to the expected root
     * @param leafHash - The leaf hash to verify
     * @param proofPath - The proof path from getProofPath
     * @param expectedRoot - The expected root hash
     * @returns True if proof is valid
     */
    static verifyProof(
        leafHash: string,
        proofPath: ProofPathElement[],
        expectedRoot: string
    ): boolean {
        if (!expectedRoot) return false;
        if (proofPath.length === 0) return leafHash === expectedRoot;

        let currentHash = leafHash;

        for (const step of proofPath) {
            if (step.siblingHash === step.eventHash) {
                // Self-paired (promoted node)
                continue;
            }

            // Hash pair with sibling
            if (step.position === 'left') {
                // Sibling is on left, current is on right
                currentHash = MerkleTree.hashPairStatic(step.siblingHash, currentHash);
            } else {
                // Sibling is on right, current is on left
                currentHash = MerkleTree.hashPairStatic(currentHash, step.siblingHash);
            }
        }

        return currentHash === expectedRoot;
    }

    /**
     * Static version of hashPair for verification
     */
    private static hashPairStatic(left: string, right: string): string {
        if (left <= right) {
            return sha3Concat(left, right);
        }
        return sha3Concat(right, left);
    }

    /**
     * Export tree structure for debugging/inspection
     * @returns Complete tree export
     */
    export(): TreeExport {
        // Reconstruct levels from nodes map
        const height = this.getHeight();
        const levels: string[][] = [];

        for (let level = 0; level < height; level++) {
            const levelNodes: string[] = [];
            const nodesAtLevel = this.countNodesAtLevel(level);

            for (let i = 0; i < nodesAtLevel; i++) {
                const key = `${level}:${i}`;
                const hash = this.nodes.get(key);
                if (hash) {
                    levelNodes.push(hash);
                }
            }

            if (levelNodes.length > 0) {
                levels.push(levelNodes);
            }
        }

        return {
            leaves: [...this.leaves],
            levels,
            rootHash: this.getRootHash(),
            leafCount: this.leaves.length
        };
    }

    /**
     * Get leaf hash by index
     * @param index - Leaf index
     * @returns Leaf hash or undefined if out of bounds
     */
    getLeaf(index: number): string | undefined {
        return this.leaves[index];
    }
}
