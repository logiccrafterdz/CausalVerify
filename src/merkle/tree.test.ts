/**
 * Merkle Tree Utility Tests
 */

import { describe, it, expect } from 'vitest';
import { MerkleTree } from './tree.js';
import { sha3 } from '../crypto/sha3.js';

describe('MerkleTree', () => {
    describe('basic properties', () => {
        it('should handle constructor with leaves', () => {
            const leaves = [sha3('1'), sha3('2')];
            const tree = new MerkleTree(leaves);
            expect(tree.getLeafCount()).toBe(2);
            expect(tree.getRootHash()).toBeDefined();
            expect(tree.getRootHash().length).toBe(66);
        });

        it('should handle empty constructor', () => {
            const tree = new MerkleTree();
            expect(tree.getLeafCount()).toBe(0);
            expect(tree.getRootHash()).toBe('');

            // Single leaf
            tree.append(sha3('1'));
            expect(tree.getRootHash()).toBe(sha3('1'));
        });
    });

    describe('inclusion and edge cases', () => {
        it('should handle verification and paths', () => {
            const tree = new MerkleTree();
            tree.append(sha3('1'));
            tree.append(sha3('2'));
            tree.append(sha3('3'));
            const root = tree.getRootHash();

            expect(MerkleTree.verifyProof(sha3('1'), tree.getProofPath(0), root)).toBe(true);
            expect(MerkleTree.verifyProof(sha3('2'), tree.getProofPath(1), root)).toBe(true);
            expect(MerkleTree.verifyProof(sha3('3'), tree.getProofPath(2), root)).toBe(true);

            expect(() => tree.getProofPath(-1)).toThrow();
            expect(MerkleTree.verifyProof('a', [], '')).toBe(false);
            expect(tree.getLeaf(0)).toBeDefined();

            // Branch: step.siblingHash === step.eventHash (covered by tree.append(3))
        });
    });
});
