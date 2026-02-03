/**
 * Causal Event Registry Tests
 */

import { describe, it, expect } from 'vitest';
import { CausalEventRegistry } from './registry.js';
import { sha3 } from '../crypto/sha3.js';

describe('CausalEventRegistry', () => {
    const agentId = '0xAgent';

    describe('initialization', () => {
        it('should initialize with an agent ID', () => {
            const registry = new CausalEventRegistry(agentId);
            expect(registry.getAgentId()).toBe(agentId);
            expect(registry.getEventCount()).toBe(0);
        });

        it('should throw if agent ID is empty', () => {
            expect(() => new CausalEventRegistry('')).toThrow('agentId is required');
        });
    });

    describe('event registration', () => {
        it('should register a first event with null predecessor', () => {
            const registry = new CausalEventRegistry(agentId);
            const event = registry.registerEvent({
                agentId,
                actionType: 'request',
                payloadHash: sha3('payload'),
                predecessorHash: null,
                timestamp: Date.now()
            });

            expect(event.predecessorHash).toBeNull();
            expect(registry.getEventCount()).toBe(1);
            expect(registry.getEvent(event.causalEventId)).toEqual(event);
        });

        it('should throw if agent ID mismatch', () => {
            const registry = new CausalEventRegistry(agentId);
            expect(() => registry.registerEvent({
                agentId: '0xWrong',
                actionType: 'request',
                payloadHash: sha3('p'),
                predecessorHash: null,
                timestamp: Date.now()
            })).toThrow('Agent ID mismatch');
        });

        it('should throw if action type is invalid', () => {
            const registry = new CausalEventRegistry(agentId);
            expect(() => registry.registerEvent({
                agentId,
                actionType: 'invalid' as any,
                payloadHash: sha3('p'),
                predecessorHash: null,
                timestamp: Date.now()
            })).toThrow('Invalid action type');
        });

        it('should enforce causal chain continuity', () => {
            const registry = new CausalEventRegistry(agentId);
            const e1 = registry.registerEvent({
                agentId,
                actionType: 'request',
                payloadHash: sha3('p1'),
                predecessorHash: null,
                timestamp: Date.now()
            });

            expect(() => registry.registerEvent({
                agentId,
                actionType: 'response',
                payloadHash: sha3('p2'),
                predecessorHash: '0xWrongHash',
                timestamp: Date.now()
            })).toThrow('Invalid predecessor hash');
        });

        it('should link events correctly in sequence', () => {
            const registry = new CausalEventRegistry(agentId);
            const e1 = registry.registerEvent({
                agentId,
                actionType: 'request',
                payloadHash: sha3('p1'),
                predecessorHash: null,
                timestamp: Date.now()
            });

            const e2 = registry.registerEvent({
                agentId,
                actionType: 'response',
                payloadHash: sha3('p2'),
                predecessorHash: e1.eventHash,
                timestamp: Date.now()
            });

            expect(e2.predecessorHash).toBe(e1.eventHash);
            expect(registry.getLastEventHash()).toBe(e2.eventHash);

            // Branch: subsequent event with null predecessor (allowed but covered)
            registry.registerEvent({
                agentId,
                actionType: 'request',
                payloadHash: sha3('p3'),
                predecessorHash: null,
                timestamp: Date.now()
            });
        });
    });

    describe('queries and export', () => {
        it('should return event by hash', () => {
            const registry = new CausalEventRegistry(agentId);
            const event = registry.registerEvent({ agentId, actionType: 'request', payloadHash: sha3('1'), predecessorHash: null, timestamp: Date.now() });
            expect(registry.getEventByHash(event.eventHash)).toEqual(event);
            expect(registry.getEventByHash('0xNonExistent')).toBeNull();
            expect(registry.getEvent('NonExistent')).toBeNull();
        });

        it('should retrieve causal chain', () => {
            const registry = new CausalEventRegistry(agentId);
            const e1 = registry.registerEvent({ agentId, actionType: 'request', payloadHash: sha3('1'), predecessorHash: null, timestamp: Date.now() });
            const e2 = registry.registerEvent({ agentId, actionType: 'response', payloadHash: sha3('2'), predecessorHash: e1.eventHash, timestamp: Date.now() });

            const chain = registry.getEventChain(e2.causalEventId, 5);
            expect(chain).toEqual([e1, e2]);
        });

        it('should handle broken chains gracefully', () => {
            const registry = new CausalEventRegistry(agentId);
            const event1 = registry.registerEvent({ agentId, actionType: 'request', payloadHash: sha3('1'), predecessorHash: null, timestamp: 1000 });
            const event2 = registry.registerEvent({ agentId, actionType: 'response', payloadHash: sha3('2'), predecessorHash: event1.eventHash, timestamp: 2000 });

            // Manually corrupt internal mapping to trigger "Chain broken" branch
            // @ts-ignore
            registry.eventsByHash.delete(event1.eventHash);

            const chain = registry.getEventChain(event2.causalEventId, 5);
            expect(chain.length).toBe(1);
            expect(chain[0].eventHash).toBe(event2.eventHash);
        });

        it('should handle non-existent event in chain request', () => {
            const registry = new CausalEventRegistry(agentId);
            const chain = registry.getEventChain('non-existent');
            expect(chain).toEqual([]);
        });

        it('should verify inclusion', () => {
            const registry = new CausalEventRegistry(agentId);
            const event = registry.registerEvent({ agentId, actionType: 'request', payloadHash: sha3('1'), predecessorHash: null, timestamp: Date.now() });
            expect(registry.verifyEventInclusion(event.eventHash)).toBe(true);
            expect(registry.verifyEventInclusion('0xWrong')).toBe(false);
            expect(registry.getProofPath('0xWrong')).toBeNull();
        });

        it('should export registry state', () => {
            const registry = new CausalEventRegistry(agentId);
            registry.registerEvent({ agentId, actionType: 'request', payloadHash: sha3('1'), predecessorHash: null, timestamp: Date.now() });
            const exported = registry.export();
            expect(exported.agentId).toBe(agentId);
            expect(exported.events.length).toBe(1);
            expect(exported.tree).toBeDefined();
        });
    });
});
