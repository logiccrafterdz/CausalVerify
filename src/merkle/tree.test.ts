/**
 * Merkle Tree Tests
 * Validates tree operations and proof generation
 */

import { describe, it, expect } from 'vitest';
import { MerkleTree } from './tree.js';
import { sha3 } from '../crypto/sha3.js';

describe('MerkleTree', () => {
    describe('constructor', () => {
        it('should create empty tree', () => {
            const tree = new MerkleTree();
            expect(tree.getLeafCount()).toBe(0);
            expect(tree.getRootHash()).toBe('');
        });

        it('should accept initial leaves', () => {
            const leaves = [sha3('a'), sha3('b'), sha3('c')];
            const tree = new MerkleTree(leaves);
            expect(tree.getLeafCount()).toBe(3);
        });
    });

    describe('append', () => {
        it('should return leaf hash as root for single leaf', () => {
            const tree = new MerkleTree();
            const leafHash = sha3('test');
            const root = tree.append(leafHash);
            expect(root).toBe(leafHash);
            expect(tree.getLeafCount()).toBe(1);
        });

        it('should compute consistent root for same leaves', () => {
            const tree1 = new MerkleTree();
            const tree2 = new MerkleTree();

            tree1.append(sha3('a'));
            tree1.append(sha3('b'));

            tree2.append(sha3('a'));
            tree2.append(sha3('b'));

            expect(tree1.getRootHash()).toBe(tree2.getRootHash());
        });

        it('should produce different roots for different leaves', () => {
            const tree1 = new MerkleTree();
            const tree2 = new MerkleTree();

            tree1.append(sha3('a'));
            tree2.append(sha3('b'));

            expect(tree1.getRootHash()).not.toBe(tree2.getRootHash());
        });

        it('should handle many appends', () => {
            const tree = new MerkleTree();
            const roots: string[] = [];

            for (let i = 0; i < 100; i++) {
                const root = tree.append(sha3(`leaf-${i}`));
                roots.push(root);
            }

            expect(tree.getLeafCount()).toBe(100);
            // Each append should produce a different root
            const uniqueRoots = new Set(roots);
            expect(uniqueRoots.size).toBe(100);
        });
    });

    describe('getProofPath', () => {
        it('should throw for out of bounds index', () => {
            const tree = new MerkleTree();
            tree.append(sha3('test'));

            expect(() => tree.getProofPath(-1)).toThrow();
            expect(() => tree.getProofPath(1)).toThrow();
        });

        it('should return empty path for single leaf', () => {
            const tree = new MerkleTree();
            tree.append(sha3('test'));

            const path = tree.getProofPath(0);
            expect(path.length).toBe(0);
        });

        it('should return valid path for two leaves', () => {
            const tree = new MerkleTree();
            tree.append(sha3('a'));
            tree.append(sha3('b'));

            const path = tree.getProofPath(0);
            expect(path.length).toBeGreaterThan(0);
            expect(path[0].position).toBe('right');
        });

        it('should include sibling at each level', () => {
            const tree = new MerkleTree();
            for (let i = 0; i < 8; i++) {
                tree.append(sha3(`leaf-${i}`));
            }

            const path = tree.getProofPath(3);
            // For 8 leaves, tree height is 3
            expect(path.length).toBe(3);
        });
    });

    describe('verifyProof', () => {
        it('should verify valid proof', () => {
            const tree = new MerkleTree();
            const leafHash = sha3('test-leaf');
            tree.append(leafHash);
            tree.append(sha3('other'));

            const proofPath = tree.getProofPath(0);
            const root = tree.getRootHash();

            expect(MerkleTree.verifyProof(leafHash, proofPath, root)).toBe(true);
        });

        it('should reject proof with wrong leaf hash', () => {
            const tree = new MerkleTree();
            tree.append(sha3('a'));
            tree.append(sha3('b'));

            const proofPath = tree.getProofPath(0);
            const root = tree.getRootHash();

            expect(MerkleTree.verifyProof(sha3('wrong'), proofPath, root)).toBe(false);
        });

        it('should reject proof with wrong root', () => {
            const tree = new MerkleTree();
            const leafHash = sha3('test');
            tree.append(leafHash);
            tree.append(sha3('other'));

            const proofPath = tree.getProofPath(0);

            expect(MerkleTree.verifyProof(leafHash, proofPath, sha3('wrong-root'))).toBe(false);
        });

        it('should handle empty tree verification', () => {
            expect(MerkleTree.verifyProof(sha3('leaf'), [], '')).toBe(false);
        });

        it('should verify single-leaf tree with empty path', () => {
            const leaf = sha3('only');
            expect(MerkleTree.verifyProof(leaf, [], leaf)).toBe(true);
        });

        it('should reject if sibling hash is tampered', () => {
            const tree = new MerkleTree();
            tree.append(sha3('a'));
            tree.append(sha3('b'));

            const proofPath = tree.getProofPath(0);
            const root = tree.getRootHash();

            // Tamper sibling hash
            proofPath[0].siblingHash = sha3('tampered');

            expect(MerkleTree.verifyProof(sha3('a'), proofPath, root)).toBe(false);
        });

        it('should verify proofs for all leaves', () => {
            const tree = new MerkleTree();
            const leaves: string[] = [];

            for (let i = 0; i < 16; i++) {
                const leaf = sha3(`leaf-${i}`);
                leaves.push(leaf);
                tree.append(leaf);
            }

            const root = tree.getRootHash();

            for (let i = 0; i < 16; i++) {
                const proofPath = tree.getProofPath(i);
                expect(MerkleTree.verifyProof(leaves[i], proofPath, root)).toBe(true);
            }
        });
    });

    describe('export', () => {
        it('should export empty tree', () => {
            const tree = new MerkleTree();
            const exported = tree.export();

            expect(exported.leaves).toEqual([]);
            expect(exported.levels).toEqual([]);
            expect(exported.rootHash).toBe('');
            expect(exported.leafCount).toBe(0);
        });

        it('should export populated tree', () => {
            const tree = new MerkleTree();
            tree.append(sha3('a'));
            tree.append(sha3('b'));

            const exported = tree.export();

            expect(exported.leaves.length).toBe(2);
            expect(exported.leafCount).toBe(2);
            expect(exported.rootHash).toBe(tree.getRootHash());
        });
    });

    describe('getLeaf', () => {
        it('should return correct leaf', () => {
            const tree = new MerkleTree();
            const leaf1 = sha3('first');
            const leaf2 = sha3('second');

            tree.append(leaf1);
            tree.append(leaf2);

            expect(tree.getLeaf(0)).toBe(leaf1);
            expect(tree.getLeaf(1)).toBe(leaf2);
        });

        it('should return undefined for out of bounds', () => {
            const tree = new MerkleTree();
            expect(tree.getLeaf(0)).toBeUndefined();
        });
    });

    describe('performance: 1000 events', () => {
        it('should handle 1000 events efficiently', () => {
            const tree = new MerkleTree();
            const start = performance.now();

            for (let i = 0; i < 1000; i++) {
                tree.append(sha3(`event-${i}`));
            }

            const elapsed = performance.now() - start;

            expect(tree.getLeafCount()).toBe(1000);
            expect(tree.getRootHash()).toMatch(/^0x[a-f0-9]{64}$/);

            // Should complete in reasonable time (< 5 seconds for 1000 events)
            expect(elapsed).toBeLessThan(5000);
        });

        it('should generate valid proofs for 1000 events', () => {
            const tree = new MerkleTree();
            const leaves: string[] = [];

            for (let i = 0; i < 1000; i++) {
                const leaf = sha3(`event-${i}`);
                leaves.push(leaf);
                tree.append(leaf);
            }

            const root = tree.getRootHash();

            // Verify random samples
            const indices = [0, 99, 500, 777, 999];
            for (const idx of indices) {
                const proofPath = tree.getProofPath(idx);
                expect(MerkleTree.verifyProof(leaves[idx], proofPath, root)).toBe(true);
            }
        });
    });
});
