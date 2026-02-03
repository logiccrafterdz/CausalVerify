/**
 * Causal Event Registry Tests
 * Validates event registration and causal chain integrity
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { CausalEventRegistry } from './registry.js';
import { sha3 } from '../crypto/sha3.js';
import { isValidUUIDv7 } from '../crypto/uuid.js';
import { MerkleTree } from '../merkle/tree.js';
import type { EventInput } from '../types/index.js';

describe('CausalEventRegistry', () => {
    const TEST_AGENT_ID = '0x1234567890abcdef1234567890abcdef12345678';
    let registry: CausalEventRegistry;

    beforeEach(() => {
        registry = new CausalEventRegistry(TEST_AGENT_ID);
    });

    describe('constructor', () => {
        it('should create registry with agent ID', () => {
            expect(registry.getAgentId()).toBe(TEST_AGENT_ID);
            expect(registry.getEventCount()).toBe(0);
        });

        it('should throw for empty agent ID', () => {
            expect(() => new CausalEventRegistry('')).toThrow();
            expect(() => new CausalEventRegistry('   ')).toThrow();
        });
    });

    describe('registerEvent', () => {
        it('should register first event with null predecessor', () => {
            const input: EventInput = {
                agentId: TEST_AGENT_ID,
                actionType: 'request',
                payloadHash: sha3('payload'),
                predecessorHash: null,
                timestamp: Date.now()
            };

            const event = registry.registerEvent(input);

            expect(isValidUUIDv7(event.causalEventId)).toBe(true);
            expect(event.eventHash).toMatch(/^0x[a-f0-9]{64}$/);
            expect(event.positionInTree).toBe(0);
            expect(event.treeRootHash).toBe(event.eventHash);
        });

        it('should register subsequent events with valid predecessor', () => {
            const first = registry.registerEvent({
                agentId: TEST_AGENT_ID,
                actionType: 'request',
                payloadHash: sha3('first'),
                predecessorHash: null,
                timestamp: Date.now()
            });

            const second = registry.registerEvent({
                agentId: TEST_AGENT_ID,
                actionType: 'response',
                payloadHash: sha3('second'),
                predecessorHash: first.eventHash,
                timestamp: Date.now()
            });

            expect(second.positionInTree).toBe(1);
            expect(second.predecessorHash).toBe(first.eventHash);
        });

        it('should throw for invalid predecessor hash', () => {
            expect(() => registry.registerEvent({
                agentId: TEST_AGENT_ID,
                actionType: 'request',
                payloadHash: sha3('test'),
                predecessorHash: sha3('nonexistent'),
                timestamp: Date.now()
            })).toThrow('Invalid predecessor hash');
        });

        it('should throw for wrong agent ID', () => {
            expect(() => registry.registerEvent({
                agentId: 'wrong-agent-id',
                actionType: 'request',
                payloadHash: sha3('test'),
                predecessorHash: null,
                timestamp: Date.now()
            })).toThrow('Agent ID mismatch');
        });

        it('should throw for invalid action type', () => {
            expect(() => registry.registerEvent({
                agentId: TEST_AGENT_ID,
                actionType: 'invalid' as any,
                payloadHash: sha3('test'),
                predecessorHash: null,
                timestamp: Date.now()
            })).toThrow('Invalid action type');
        });

        it('should handle all valid action types', () => {
            const actionTypes = ['request', 'response', 'error', 'state_transition'] as const;
            let prevHash: string | null = null;

            for (const actionType of actionTypes) {
                const event = registry.registerEvent({
                    agentId: TEST_AGENT_ID,
                    actionType,
                    payloadHash: sha3(actionType),
                    predecessorHash: prevHash,
                    timestamp: Date.now()
                });

                expect(event.actionType).toBe(actionType);
                prevHash = event.eventHash;
            }

            expect(registry.getEventCount()).toBe(4);
        });
    });

    describe('getEvent', () => {
        it('should retrieve event by ID', () => {
            const registered = registry.registerEvent({
                agentId: TEST_AGENT_ID,
                actionType: 'request',
                payloadHash: sha3('test'),
                predecessorHash: null,
                timestamp: Date.now()
            });

            const retrieved = registry.getEvent(registered.causalEventId);

            expect(retrieved).toEqual(registered);
        });

        it('should return null for unknown ID', () => {
            expect(registry.getEvent('unknown-id')).toBeNull();
        });
    });

    describe('getEventByHash', () => {
        it('should retrieve event by hash', () => {
            const registered = registry.registerEvent({
                agentId: TEST_AGENT_ID,
                actionType: 'request',
                payloadHash: sha3('test'),
                predecessorHash: null,
                timestamp: Date.now()
            });

            const retrieved = registry.getEventByHash(registered.eventHash);

            expect(retrieved).toEqual(registered);
        });

        it('should return null for unknown hash', () => {
            expect(registry.getEventByHash(sha3('unknown'))).toBeNull();
        });
    });

    describe('getEventChain', () => {
        it('should return chain in causal order', () => {
            const events: any[] = [];
            let prevHash: string | null = null;

            for (let i = 0; i < 5; i++) {
                const event = registry.registerEvent({
                    agentId: TEST_AGENT_ID,
                    actionType: 'request',
                    payloadHash: sha3(`event-${i}`),
                    predecessorHash: prevHash,
                    timestamp: Date.now() + i
                });
                events.push(event);
                prevHash = event.eventHash;
            }

            const chain = registry.getEventChain(events[4].causalEventId, 10);

            expect(chain.length).toBe(5);
            expect(chain[0].causalEventId).toBe(events[0].causalEventId);
            expect(chain[4].causalEventId).toBe(events[4].causalEventId);
        });

        it('should respect depth limit', () => {
            let prevHash: string | null = null;
            let lastEventId = '';

            for (let i = 0; i < 10; i++) {
                const event = registry.registerEvent({
                    agentId: TEST_AGENT_ID,
                    actionType: 'request',
                    payloadHash: sha3(`event-${i}`),
                    predecessorHash: prevHash,
                    timestamp: Date.now() + i
                });
                prevHash = event.eventHash;
                lastEventId = event.causalEventId;
            }

            const chain = registry.getEventChain(lastEventId, 4);

            // total chain length including target = 4
            expect(chain.length).toBe(4);
        });

        it('should return empty array for unknown event', () => {
            expect(registry.getEventChain('unknown-id', 5)).toEqual([]);
        });
    });

    describe('getProofPath', () => {
        it('should return proof path for event', () => {
            registry.registerEvent({
                agentId: TEST_AGENT_ID,
                actionType: 'request',
                payloadHash: sha3('test'),
                predecessorHash: null,
                timestamp: Date.now()
            });

            const second = registry.registerEvent({
                agentId: TEST_AGENT_ID,
                actionType: 'response',
                payloadHash: sha3('response'),
                predecessorHash: registry.getLastEventHash(),
                timestamp: Date.now()
            });

            const proofPath = registry.getProofPath(second.causalEventId);

            expect(proofPath).not.toBeNull();
            expect(Array.isArray(proofPath)).toBe(true);
        });

        it('should return null for unknown event', () => {
            expect(registry.getProofPath('unknown')).toBeNull();
        });
    });

    describe('verifyEventInclusion', () => {
        it('should verify included event', () => {
            const event = registry.registerEvent({
                agentId: TEST_AGENT_ID,
                actionType: 'request',
                payloadHash: sha3('test'),
                predecessorHash: null,
                timestamp: Date.now()
            });

            expect(registry.verifyEventInclusion(event.eventHash)).toBe(true);
        });

        it('should reject unknown event hash', () => {
            expect(registry.verifyEventInclusion(sha3('unknown'))).toBe(false);
        });
    });

    describe('export', () => {
        it('should export empty registry', () => {
            const exported = registry.export();

            expect(exported.agentId).toBe(TEST_AGENT_ID);
            expect(exported.events).toEqual([]);
            expect(exported.tree.leafCount).toBe(0);
        });

        it('should export populated registry', () => {
            registry.registerEvent({
                agentId: TEST_AGENT_ID,
                actionType: 'request',
                payloadHash: sha3('test'),
                predecessorHash: null,
                timestamp: Date.now()
            });

            const exported = registry.export();

            expect(exported.events.length).toBe(1);
            expect(exported.tree.leafCount).toBe(1);
        });

        it('should export events in order', () => {
            let prevHash: string | null = null;

            for (let i = 0; i < 5; i++) {
                const event = registry.registerEvent({
                    agentId: TEST_AGENT_ID,
                    actionType: 'request',
                    payloadHash: sha3(`event-${i}`),
                    predecessorHash: prevHash,
                    timestamp: Date.now() + i
                });
                prevHash = event.eventHash;
            }

            const exported = registry.export();

            for (let i = 0; i < 5; i++) {
                expect(exported.events[i].positionInTree).toBe(i);
            }
        });
    });

    describe('getRootHash', () => {
        it('should return empty string for empty registry', () => {
            expect(registry.getRootHash()).toBe('');
        });

        it('should return current root', () => {
            registry.registerEvent({
                agentId: TEST_AGENT_ID,
                actionType: 'request',
                payloadHash: sha3('test'),
                predecessorHash: null,
                timestamp: Date.now()
            });

            expect(registry.getRootHash()).toMatch(/^0x[a-f0-9]{64}$/);
        });
    });

    describe('getLastEventHash', () => {
        it('should return null for empty registry', () => {
            expect(registry.getLastEventHash()).toBeNull();
        });

        it('should return last registered event hash', () => {
            const first = registry.registerEvent({
                agentId: TEST_AGENT_ID,
                actionType: 'request',
                payloadHash: sha3('first'),
                predecessorHash: null,
                timestamp: Date.now()
            });

            expect(registry.getLastEventHash()).toBe(first.eventHash);

            const second = registry.registerEvent({
                agentId: TEST_AGENT_ID,
                actionType: 'response',
                payloadHash: sha3('second'),
                predecessorHash: first.eventHash,
                timestamp: Date.now()
            });

            expect(registry.getLastEventHash()).toBe(second.eventHash);
        });
    });
});
