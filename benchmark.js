import { CausalEventRegistry, ProofGenerator, verifyProof, generateKeyPair, sha3 } from './dist/index.js';

async function runBenchmark() {
    console.log("Starting benchmark...");
    const iterations = 100; // Reduced for initial debugging
    const { privateKey, publicKey } = generateKeyPair();
    const registry = new CausalEventRegistry('agent');

    console.log("Warming up (100 events)...");
    for (let i = 0; i < 100; i++) {
        registry.registerEvent({
            agentId: 'agent',
            actionType: 'request',
            payloadHash: sha3(i.toString()),
            predecessorHash: i === 0 ? null : registry.getLastEventHash(),
            timestamp: Date.now()
        });
    }
    const generator = new ProofGenerator(registry);
    const events = registry.events;
    const lastId = Array.from(events.keys()).pop();

    const proofTimes = [];
    const verifyTimes = [];

    console.log(`Running ${iterations} iterations (Signing is slow in pure JS)...`);
    for (let i = 0; i < iterations; i++) {
        if (i % 10 === 0) console.log(`Iteration ${i}...`);

        const startP = performance.now();
        const proof = generator.generateProof(lastId, privateKey);
        const endP = performance.now();
        proofTimes.push(endP - startP);

        const startV = performance.now();
        verifyProof(proof, 'agent', publicKey);
        const endV = performance.now();
        verifyTimes.push(endV - startV);
    }

    const avg = arr => arr.reduce((a, b) => a + b, 0) / arr.length;
    const p99 = arr => {
        const sorted = [...arr].sort((a, b) => a - b);
        return sorted[Math.floor(sorted.length * 0.99)];
    };

    console.log("\n--- Benchmark Results ---");
    console.log(`Proof Generation p99: ${p99(proofTimes).toFixed(4)}ms`);
    console.log(`Proof Verification p99: ${p99(verifyTimes).toFixed(4)}ms`);
    console.log(`Avg total roundtrip: ${(avg(proofTimes) + avg(verifyTimes)).toFixed(4)}ms`);
}

runBenchmark().catch(console.error);
