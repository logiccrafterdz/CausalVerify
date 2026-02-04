import {
    CausalEventRegistry,
    ProofGenerator,
    generateKeyPair,
    sha3,
    ProgressiveVerifier
} from './dist/index.js';

async function runBenchmark() {
    console.log("--- Progressive Verification Benchmark ---");
    const { privateKey, publicKey } = generateKeyPair();
    const agentId = '0xAgent';
    const registry = new CausalEventRegistry(agentId);

    // Register some history
    for (let i = 0; i < 5; i++) {
        registry.registerEvent({
            agentId,
            actionType: 'request',
            payloadHash: sha3(i.toString()),
            predecessorHash: i === 0 ? null : registry.getLastEventHash(),
            timestamp: Date.now()
        });
    }

    const generator = new ProofGenerator(registry);
    const events = registry.events;
    const lastEventId = Array.from(events.keys()).pop();
    const fullProof = generator.generateProof(lastEventId, privateKey);

    // Generate manual LightProof for test
    const lightProof = {
        agentId,
        targetEventHash: fullProof.targetEvent.eventHash,
        causalChain: fullProof.causalChain.map(el => ({ eventHash: el.eventHash, timestamp: el.timestamp })),
        timestamp: Date.now()
    };

    const verifier = new ProgressiveVerifier();

    console.log("Measuring Immediate Trust (< 5ms target)...");
    const startL = performance.now();
    const resultL = await verifier.verify({ light: lightProof }, { agentId });
    const endL = performance.now();
    console.log(`Immediate Trust took: ${(endL - startL).toFixed(4)}ms`);
    console.log(`Can proceed: ${resultL.canProceed}`);

    console.log("\nMeasuring Deferred Crypto Verification (Full Security)...");
    const startF = performance.now();
    const resultF = await verifier.verify({ light: lightProof, full: fullProof }, { agentId, publicKey });
    const endF = performance.now();
    console.log(`Progressive initialization took: ${(endF - startF).toFixed(4)}ms`);

    const startFull = performance.now();
    const fullRes = await resultF.fullResult;
    const endFull = performance.now();
    console.log(`Full cryptographic verification took: ${(endFull - startFull).toFixed(4)}ms`);
    console.log(`Final crypto validity: ${fullRes.isValid}`);
}

runBenchmark().catch(console.error);
