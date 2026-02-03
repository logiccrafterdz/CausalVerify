# CausalVerify - Causal Behavioral Proofs Library

Version 1.0 - Protocol-Level Contribution to x402/ERC-8004 Ecosystem

## Core Vision

A lightweight, protocol-agnostic library that provides Causal Behavioral Verification as a trust layer ABOVE payment protocols (x402) and identity standards (ERC-8004).

**Key Insight:**
- Payment (x402) answers "Did payment occur?"
- Identity (ERC-8004) answers "Who performed the action?"
- CAUSAL PROOFS answer "WHAT exactly happened and in what causal order?" - the missing trust primitive.

**Strategic Position:**
Not a marketplace. Not an agent. A verifiable behavior layer that ANY agent/marketplace can integrate to prove integrity of agent-to-agent interactions without centralized validation.

---

## Non-Negotiable Constraints

- Zero external API dependencies (stateless, self-contained)
- HTTP Local (localhost:9876) compatible for development/debugging
- Production-ready cryptographic primitives (no experimental crypto)
- Professional tone - zero emojis in code/docs
- Architectural longevity - must survive toolchain changes
- Privacy-first - proofs reveal behavior without exposing raw agent internals
- Target audience: developers building agents (not end-users)
- Must integrate cleanly with x402 payment flow

---

## Functional Requirements

### 1. Causal Event Registry

Register atomic agent actions as causally-ordered events using Nonce-ordered Merkle Trees.

**Input:**
- `agentId` (ERC-8004 compliant address or identifier)
- `actionType` (string enum: 'request', 'response', 'error', 'state_transition')
- `payloadHash` (SHA-256 of action payload - never raw payload)
- `predecessorHash` (hash of immediately preceding causal event - null for root)
- `timestamp` (Unix epoch - verified client-side only, not trusted)

**Output:**
- `causalEventId` (UUIDv7)
- `eventHash` (SHA3-256 of concatenated fields)
- `positionInTree` (uint256 - Merkle tree leaf index)
- `treeRootHash` (current root of agent's causal tree)

**Critical Rule:** Each event MUST reference its immediate causal predecessor. Breaking causality = invalid proof.

### 2. Atomic Proof Generation

Generate minimal cryptographic proof that a specific causal sequence occurred.

**Output Structure:**
```json
{
  "targetEvent": { },
  "proofPath": [
    { "eventHash": "0x...", "siblingHash": "0x...", "position": "left|right" }
  ],
  "causalChain": [
    { "eventHash": "0x...", "actionType": "...", "timestamp": 0, "predecessorHash": "0x..." }
  ],
  "treeRootHash": "0x...",
  "agentSignature": "0x..."
}
```

### 3. x402 Integration Layer

Seamlessly attach causal proofs to x402 payment flows WITHOUT modifying x402 spec.

**Headers:**
- `X-Causal-Proof`: base64(JSON proof)
- `X-Causal-Proof-Schema`: "causal-v1"

### 4. Verification Engine (Stateless)

Pure function that verifies a causal proof WITHOUT network calls or state.

---

## Non-Functional Requirements

| Category | Requirement |
|----------|-------------|
| Performance | Proof generation < 5ms for chains <= 100 events |
| Size | Core library < 50KB minified (no deps) |
| Security | All hashes use SHA3-256 |
| Test Coverage | >= 95% branch coverage |
| Compatibility | Node.js 18+, Bun, Deno, browser |

---

## Development Timeline

| Week | Deliverable |
|------|-------------|
| 1 | Core Causal Event Registry + Merkle Tree implementation |
| 2 | Atomic Proof Generation + Verification Engine |
| 3 | x402 Integration Layer + Semantic Rules Engine |
| 4 | Production Package + Documentation |

---

## Quality Gates

- 100% of unit tests pass
- >= 95% branch coverage
- Zero npm dependencies
- Works in browser without bundler (ESM module)
- Proof verification time < 10ms for chains <= 50 events
- Full integration test with mock x402 flow
