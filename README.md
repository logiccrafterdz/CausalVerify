# CausalVerify

A lightweight, protocol-agnostic library for **Causal Behavioral Verification**.

CausalVerify acts as a trust layer for autonomous agents and payment protocols (like x402), providing cryptographic proof that events happened in a specific causal order.

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

## Core Components

- **CausalEventRegistry**: The main interface for managing events and their causal links.
- **MerkleTree**: Underpins the registry to provide verifiable state commitment.
- **Crypto Utilities**: Optimized SHA3-256 and UUIDv7 implementations.

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Check coverage
npm run test:coverage

# Build for production
npm run build
```

## Security

CausalVerify uses standard SHA3-256 for hashing and RFC-compliant UUIDv7 for ordering. It is designed to be privacy-preserving by only storing hashes of payloads in the Merkle Tree.

## License

MIT
