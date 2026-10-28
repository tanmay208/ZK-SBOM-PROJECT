import { Noir } from '@noir-lang/noir_js';
import fs from 'fs';

async function main() {
    const args = process.argv.slice(2);
    if (args.length < 3) {
        console.error("Usage: node execute_acvm.mjs <circuit.json> <inputs.json> <output_witness.gz>");
        process.exit(1);
    }

    const [circuitPath, inputsPath, outputPath] = args;

    if (!fs.existsSync(circuitPath)) {
        console.error(`[ACVM Adapter] Error: Circuit file not found: ${circuitPath}`);
        process.exit(2);
    }
    if (!fs.existsSync(inputsPath)) {
        console.error(`[ACVM Adapter] Error: Inputs file not found: ${inputsPath}`);
        process.exit(3);
    }

    let circuitJson;
    try {
        circuitJson = JSON.parse(fs.readFileSync(circuitPath, 'utf8'));
    } catch (e) {
        console.error(`[ACVM Adapter] Error parsing circuit JSON: ${e.message}`);
        process.exit(4);
    }

    if (!circuitJson.bytecode || !circuitJson.abi) {
        console.error("[ACVM Adapter] Error: Circuit JSON missing 'bytecode' or 'abi' fields.");
        process.exit(5);
    }

    let inputs;
    try {
        inputs = JSON.parse(fs.readFileSync(inputsPath, 'utf8'));
    } catch (e) {
        console.error(`[ACVM Adapter] Error parsing inputs JSON: ${e.message}`);
        process.exit(6);
    }

    const t0 = performance.now();
    const noir = new Noir(circuitJson);
    await noir.init();

    const tExec = performance.now();
    const { witness } = await noir.execute(inputs);
    const durMs = performance.now() - tExec;

    if (!witness || !(witness instanceof Uint8Array) || witness.length < 10) {
        console.error("[ACVM Adapter] Error: Solved witness is invalid or empty.");
        process.exit(7);
    }

    // GZIP header check: 0x1f 0x8b
    if (witness[0] !== 0x1f || witness[1] !== 0x8b) {
        console.error("[ACVM Adapter] Error: Solved witness lacks valid GZIP header (0x1f, 0x8b).");
        process.exit(8);
    }

    fs.writeFileSync(outputPath, witness);
    const totalMs = performance.now() - t0;
    console.log(`[ACVM Adapter] Solved witness in ${(durMs / 1000).toFixed(3)}s (${durMs.toFixed(1)}ms), total ${(totalMs / 1000).toFixed(3)}s. Output: ${witness.length} bytes.`);
}

main().catch(err => {
    console.error("[ACVM Adapter] Execution failed:", err);
    process.exit(10);
});
