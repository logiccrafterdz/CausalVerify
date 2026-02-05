# CausalVerify

A lightweight library for causal behavioral verification in autonomous agent systems.

CausalVerify provides cryptographic proof that events happened in a specific causal order. It serves as a trust layer for payment protocols like x402, bridging identity verification and outcome validation through proven causality.

## Features

- Zero runtime dependencies (pure JavaScript/TypeScript)
- SHA3-256 hashing (FIPS 202 compliant)
- UUIDv7 for timestamp-ordered identifiers
- Merkle tree proofs with O(log n) verification
- Causal event registry with predecessor enforcement
- secp256k1 ECDSA signing (BIP-62 compliant)
- Browser and Node.js compatible

## Installation

```bash
npm install @logiccrafterdz/causal-verify
```

## Quick Start

```typescript
import { 
  CausalEventRegistry, 
  sha3, 
  ProofGenerator, 
  verifyProof,
  generateKeyPair 
} from '@logiccrafterdz/causal-verify';

// Setup
const agentId = '0xAgentID';
const { privateKey, publicKey } = generateKeyPair();
const registry = new CausalEventRegistry(agentId);

// Register an event
const event = registry.registerEvent({
  agentId,
  actionType: 'request',
  payloadHash: sha3('payload'),
  predecessorHash: null,
  timestamp: Date.now()
});

// Generate proof
const generator = new ProofGenerator(registry);
const proof = generator.generateProof(event.causalEventId, privateKey);

// Verify
const result = verifyProof(proof, agentId, publicKey);
console.log(`Valid: ${result.isValid}, Trust: ${result.trustScore}`);
```

## API Reference

### CausalEventRegistry

```typescript
const registry = new CausalEventRegistry(agentId);
registry.registerEvent(input);
registry.getEventChain(eventId, depth);
registry.generateProofPath(eventId);
```

### ProofGenerator

```typescript
const generator = new ProofGenerator(registry);
generator.generateProof(eventId, privateKey, chainDepth);
```

### Verification

```typescript
verifyProof(proof, agentId, publicKey);
verifyPrePayment(proof, agentId, publicKey, rules);
verifyCausalChain(chain, expectedHash, options);
```

## Trust Scoring

Trust scores range from 0.0 to 1.0:

- Base score (0.2): Cryptographic validity confirmed
- Chain length bonus (up to 0.4): Longer verified chains increase trust
- Recency bonus (up to 0.4): Recent events receive higher trust

Invalid proofs receive a score of 0.0.

## x402 Integration

```typescript
import { encodeCausalHeader, decodeCausalHeader, CAUSAL_PROOF_HEADER } from '@logiccrafterdz/causal-verify';

// Encode for HTTP header
const headerValue = encodeCausalHeader(proof);
response.setHeader(CAUSAL_PROOF_HEADER, headerValue);

// Decode from header
const proof = decodeCausalHeader(headerValue);
```

## Security Requirements

- Requires `crypto.getRandomValues()` API (modern browsers, Node.js 15+)
- Event timestamps must be within 5 seconds of registration time
- All payloads are stored as hashes for privacy

## Progressive Verification

For performance-critical applications:

1. Light verification (under 1ms): Fast metadata and chain continuity check
2. Full verification (around 150ms): Complete cryptographic validation

```typescript
import { ProgressiveVerifier } from '@logiccrafterdz/causal-verify';

const verifier = new ProgressiveVerifier();
const result = await verifier.verify(
  { light: lightProof, full: fullProof },
  { agentId, publicKey },
  { autoVerifyFull: true }
);
```

## License

MIT

