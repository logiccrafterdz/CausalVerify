# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Requirements

CausalVerify requires the following for secure operation:

- `crypto.getRandomValues()` API must be available
- Modern browsers (Chrome 43+, Firefox 36+, Safari 10.1+)
- Node.js 15+ (or Node.js 12+ with `--experimental-webcrypto`)

The library will throw an error if secure random generation is unavailable. It will not fall back to insecure alternatives.

## Cryptographic Primitives

| Primitive | Standard | Implementation |
|-----------|----------|----------------|
| Hashing | SHA3-256 | FIPS 202 |
| Signing | ECDSA secp256k1 | BIP-62 (Low-S) |
| Identifiers | UUIDv7 | RFC 9562 |

## Privacy

- Payloads are never stored directly
- Only SHA3-256 hashes of payloads are included in proofs
- Merkle trees contain only hashes, not original data

## Validation

- Event timestamps are validated against UUIDv7 registration time (5 second tolerance)
- Causal chains are verified for structural integrity and temporal ordering
- Decoded proof headers are validated against schema before use

## Reporting a Vulnerability

To report a security issue:

1. Do not open a public issue
2. Email: security@logiccrafterdz.com
3. Include a description and steps to reproduce
4. Allow 90 days for disclosure

We aim to respond within 48 hours and provide a fix timeline within 7 days.
