import {
    CausalEventRegistry,
    verifyCausalChain,
    sha3,
    encodeCausalHeader,
    decodeCausalHeader,
    ProofGenerator,
    generateKeyPair
} from './dist/index.js';

async function runAudit() {
    console.log("--- FC-01: Causal Gap Detection ---");
    const agentId = '0xAgent';
    const registry = new CausalEventRegistry(agentId);

    const e1 = registry.registerEvent({ agentId, actionType: 'request', payloadHash: sha3('1'), predecessorHash: null, timestamp: 1000 });

    // Simulate a gap by creating a chain with a skip
    const chainWithGap = [
        { eventHash: e1.eventHash, actionType: e1.actionType, timestamp: e1.timestamp, predecessorHash: e1.predecessorHash },
        { eventHash: sha3('gap'), actionType: 'state_transition', timestamp: 3000, predecessorHash: 'missing' }
    ];

    const result = verifyCausalChain(chainWithGap, sha3('gap'));
    console.log("FC-01 Result:", JSON.stringify(result));

    console.log("\n--- FC-02: Merkle Scaling ---");
    const largeRegistry = new CausalEventRegistry(agentId);
    const startBuild = performance.now();
    for (let i = 0; i < 1000; i++) {
        largeRegistry.registerEvent({
            agentId,
            actionType: 'request',
            payloadHash: sha3(i.toString()),
            predecessorHash: i === 0 ? null : largeRegistry.getLastEventHash(),
            timestamp: Date.now()
        });
    }
    const endBuild = performance.now();

    // Access internal events using string indexing to bypass TS/Private if needed (but it's just JS here)
    const events = largeRegistry.events;
    const lastEventId = Array.from(events.keys()).pop();

    const startProof = performance.now();
    const proofPath = largeRegistry.getProofPath(lastEventId);
    const endProof = performance.now();

    console.log(`Build 1000 events: ${(endBuild - startBuild).toFixed(2)}ms`);
    console.log(`Generate proof (N=1000): ${(endProof - startProof).toFixed(2)}ms`);
    console.log(`Proof path length: ${proofPath.length} (Expected log2(1000) ~ 10)`);
    console.log(`Proof size (JSON): ${JSON.stringify(proofPath).length} bytes`);

    console.log("\n--- FC-04: x402 Roundtrip ---");
    const { privateKey } = generateKeyPair();
    const generator = new ProofGenerator(largeRegistry);
    const proof = generator.generateProof(lastEventId, privateKey);

    let failures = 0;
    for (let i = 0; i < 1000; i++) {
        const encoded = encodeCausalHeader(proof);
        const decoded = decodeCausalHeader(encoded);
        if (proof.targetEvent.eventHash !== decoded.targetEvent.eventHash) failures++;
    }
    console.log(`x402 Roundtrip Failures (1000 iterations): ${failures}`);
}

runAudit().catch(console.error);
