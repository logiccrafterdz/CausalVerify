# CausalVerify

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()
[![Coverage](https://img.shields.io/badge/Coverage-80%2B%25-brightgreen.svg)]()

A lightweight, protocol-agnostic library for **Causal Behavioral Verification**.

CausalVerify acts as a trust layer for autonomous agents and payment protocols (like x402), providing cryptographic proof that events happened in a specific causal order. It bridges the gap between "Who performed an action" (Identity) and "Did it happen" (Outcome) by proving **Causality**.

## Features

- **Zero Runtime Dependencies**: Pure JavaScript/TypeScript implementation for maximum portability.
- **SHA3-256 (Keccak)**: NIST FIPS 202 compliant hashing.
- **UUIDv7**: Timestamp-ordered identifiers for guaranteed causal sorting.
- **Merkle Tree Proofs**: Efficient `O(log n)` inclusion proofs for event verification.
- **Causal Event Registry**: Enforces strict predecessor-successor relationships.
- **secp256k1 ECDSA**: Pure JS implementation for signing and verifying proofs.
- **Atomic Proof Generation**: Combined Merkle paths, causal chains, and agent signatures.
- **Stateless Verification**: Pure, side-effect-free verification of causal proofs and semantic rules.

## Installation

```bash
npm install @causal-proofs/core
```

## Quick Start

```typescript
import { 
  CausalEventRegistry, 
  sha3, 
  ProofGenerator, 
  verifyProof,
  generateKeyPair 
} from '@causal-proofs/core';

// 1. Setup
const agentId = '0xAgentID';
const { privateKey, publicKey } = generateKeyPair();
const registry = new CausalEventRegistry(agentId);

// 2. Register an event
const event = registry.registerEvent({
  agentId,
  actionType: 'request',
  payloadHash: sha3('some-payload'),
  predecessorHash: null,
  timestamp: Date.now()
});

// 3. Generate a signed causal proof
const generator = new ProofGenerator(registry);
const proof = generator.generateProof(event.causalEventId, privateKey);

// 4. Verification (stateless)
const result = verifyProof(proof, agentId, publicKey);
console.log(`Proof is valid: ${result.isValid}`);
```

## API Reference

### Core Classes

#### `CausalEventRegistry(agentId: string)`
Manages an agent's causal history.
- `registerEvent(input: EventInput): CausalEvent`: Adds a new action to the registry.
- `getEventChain(eventId: string, depth: number): CausalEvent[]`: Retrieves causal history.
- `generateProofPath(eventId: string): ProofPathElement[]`: Generates Merkle inclusion path.

#### `ProofGenerator(registry: CausalEventRegistry)`
Orchestrates proof creation.
- `generateProof(eventId: string, privateKey: string, chainDepth: number): CausalProof`: Creates a signed, multi-layered proof.

#### `SemanticRulesEngine(rules: SemanticRules)`
Validates business logic in causal chains.
- `validate(chain: CausalChainElement[]): { valid: boolean, violations: string[] }`

### Verification Functions

#### `verifyProof(proof, agentId, publicKey): VerificationResult`
Stateless cryptographic validation (Merkle + Signature + Integrity).

#### `verifyPrePayment(proof, agentId, publicKey, rules?): VerificationResult`
Orchestrated validation combining crypto and semantic rules for x402 flows.

## Trust Model

CausalVerify provides a "Trust Score" (0.0 - 1.0) based on:
- **1.0 (High Trust)**: Cryptography is valid AND semantic rules pass.
- **0.5 (Partial Trust)**: Cryptography is valid but semantic rules fail (e.g., response received before request).
- **0.0 (No Trust)**: Signature mismatch or Merkle inclusion failure.

## Quality Gates

- **100% Native**: Zero runtime dependencies.
- **Strict Security**: SHA3-256 for all hashing; UUIDv7 for temporal sorting.
- **High Coverage**: Branch coverage > 80%; exhaustive NIST/RFC verification.

## Security

CausalVerify uses standard SHA3-256 for hashing and RFC-compliant UUIDv7 for ordering. It is designed to be privacy-preserving by only storing hashes of payloads in the Merkle Tree.

## License

MIT
