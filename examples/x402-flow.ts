/**
 * CausalVerify End-to-End Example: x402 Integration Flow
 * 
 * This example demonstrates:
 * 1. Creating a CausalEventRegistry for an agent.
 * 2. Registering sequence of events (Request -> Response).
 * 3. Generating a signed CausalProof.
 * 4. Encoding the proof into an x402 header.
 * 5. Decoding and Verifying the proof using semantic rules.
 */

import {
    CausalEventRegistry,
    ProofGenerator,
    verifyPrePayment,
    encodeCausalHeader,
    decodeCausalHeader,
    generateKeyPair,
    sha3,
    CAUSAL_PROOF_HEADER
} from '../dist/index.js';

async function runExample() {
    console.log("--- CausalVerify x402 Integration Example ---\n");

    // 1. Initial Setup
    // In a real scenario, this would be the agent's persistent identity
    const agentId = '0xAgent_Alice_ERC8004';
    const { privateKey, publicKey } = generateKeyPair();
    const registry = new CausalEventRegistry(agentId);

    console.log(`[Alice] Initialized agent: ${agentId}`);
    console.log(`[Alice] Public Key: ${publicKey.substring(0, 16)}...\n`);

    // 2. Alice registers a Request event (e.g., asking for data)
    const requestEvent = registry.registerEvent({
        agentId,
        actionType: 'request',
        payloadHash: sha3(JSON.stringify({ query: 'get_weather_data', location: 'London' })),
        predecessorHash: null,
        timestamp: Date.now()
    });

    console.log(`[Alice] Registered Event: ${requestEvent.actionType} (Hash: ${requestEvent.eventHash.substring(0, 12)}...)`);

    // 3. Alice registers a Response event (simulating receiving data)
    const responseEvent = registry.registerEvent({
        agentId,
        actionType: 'response',
        payloadHash: sha3(JSON.stringify({ temperature: '22C', status: 'success' })),
        predecessorHash: requestEvent.eventHash,
        timestamp: Date.now() + 50 // 50ms later
    });

    console.log(`[Alice] Registered Event: ${responseEvent.actionType} (Hash: ${responseEvent.eventHash.substring(0, 12)}...)`);

    // 4. Alice generates a proof for the response to present to Bob (Verifier)
    const generator = new ProofGenerator(registry);
    console.log(`\n[Alice] Generating proof for event chain (depth: 2)...`);

    // We want to prove the response happened AFTER the request
    const proof = generator.generateProof(responseEvent.causalEventId, privateKey, 2);

    // 5. Serialize proof for X-Causal-Proof header
    const headerValue = encodeCausalHeader(proof);
    console.log(`[Alice] Encoded Header [${CAUSAL_PROOF_HEADER}]: ${headerValue.substring(0, 32)}...\n`);

    // --- Simulating Transmission to Bob ---

    // 6. Bob receives the proof and decodes it
    console.log(`[Bob] Received request with ${CAUSAL_PROOF_HEADER}`);
    const decodedProof = decodeCausalHeader(headerValue);

    // 7. Bob verifies the proof using semantic rules before accepting (Pre-Payment validation)
    console.log(`[Bob] Verifying proof integrity and protocol compliance...`);

    const rules = {
        requestMustPrecedeResponse: true,
        maxTimeGapMs: 1000,
        requireDirectCausality: true,
        minVerificationDepth: 2
    };

    const verificationResult = verifyPrePayment(decodedProof, agentId, publicKey, rules);

    if (verificationResult.isValid) {
        console.log(`\n✅ [Bob] VERIFICATION SUCCESS: Trust Score: ${verificationResult.trustScore}`);
        console.log(`[Bob] Verified ${verificationResult.verifiedActions} actions in causal chain.`);
        console.log(`[Bob] Alice has proven she followed the protocol correctly.`);
    } else {
        console.error(`\n❌ [Bob] VERIFICATION FAILED:`);
        verificationResult.errors.forEach(err => console.error(`  - ${err}`));
    }
}

// Run the flow
runExample().catch(console.error);
