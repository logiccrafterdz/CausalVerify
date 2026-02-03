import { describe, it, expect } from 'vitest';
import { SemanticRulesEngine } from './rules.js';
import { ActionType } from '../types/index.js';

describe('SemanticRulesEngine', () => {
    it('should cover empty chain branch', () => {
        const engine = new SemanticRulesEngine({});
        const result = engine.validate([]);
        expect(result.valid).toBe(true);
    });

    it('should cover maxTimeGapMs violation', () => {
        const engine = new SemanticRulesEngine({ maxTimeGapMs: 100 });
        const chain = [
            { eventHash: 'h1', actionType: 'request', timestamp: 100, predecessorHash: null },
            { eventHash: 'h2', actionType: 'response', timestamp: 300, predecessorHash: 'h1' }
        ];
        const result = engine.validate(chain as any);
        expect(result.valid).toBe(false);
        expect(result.violations[0]).toContain('Temporal violation');
    });

    it('should cover requiredActionTypes violation', () => {
        const engine = new SemanticRulesEngine({ requiredActionTypes: ['request', 'payment'] });
        const chain = [
            { eventHash: 'h1', actionType: 'request', timestamp: 100, predecessorHash: null }
        ];
        const result = engine.validate(chain as any);
        expect(result.valid).toBe(false);
        expect(result.violations).toContain('Missing required action type: payment');
    });

    it('should cover forbiddenActionTypes violation', () => {
        const engine = new SemanticRulesEngine({ forbiddenActionTypes: ['error'] });
        const chain = [
            { eventHash: 'h1', actionType: 'error', timestamp: 100, predecessorHash: null }
        ];
        const result = engine.validate(chain as any);
        expect(result.valid).toBe(false);
        expect(result.violations[0]).toContain('Forbidden action type detected');
    });

    it('should cover requireDirectCausality violation', () => {
        const engine = new SemanticRulesEngine({ requireDirectCausality: true });
        const chain = [
            { eventHash: 'h1', actionType: 'request', timestamp: 100, predecessorHash: null },
            { eventHash: 'h3', actionType: 'response', timestamp: 200, predecessorHash: 'h2' }
        ];
        const result = engine.validate(chain as any);
        expect(result.valid).toBe(false);
        expect(result.violations[0]).toContain('Causality violation');
    });

    it('should cover minVerificationDepth violation', () => {
        const engine = new SemanticRulesEngine({ minVerificationDepth: 5 });
        const chain = [
            { eventHash: 'h1', actionType: 'request', timestamp: 100, predecessorHash: null }
        ];
        const result = engine.validate(chain as any);
        expect(result.valid).toBe(false);
        expect(result.violations[0]).toContain('Insufficient chain depth');
    });
});
