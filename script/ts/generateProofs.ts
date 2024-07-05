import fs from "fs";
import {
	InitArgs,
	init,
	generateArgs,
	prove,
	artifactUrls,
	packGroth16Proof,
	ArtifactsOrigin,
} from "@anon-aadhaar/core";
import * as ethers from "ethers";
import { testData } from "./testData";

const signal = "0";
const calldataHash =
	"0xf24a0e5a4e8b3c3c9cf590cc09a00299c9c1cc0c73ed93fa18f5d618a9dbe147";
const nullifierSeed = 1234;

async function generateProofs() {
	const certificate = fs
		.readFileSync(__dirname + "/testCertificate.pem")
		.toString();

	const anonAadhaarInitArgs: InitArgs = {
		wasmURL: artifactUrls.v2.wasm,
		zkeyURL: artifactUrls.v2.zkey,
		vkeyURL: artifactUrls.v2.vk,
		artifactsOrigin: ArtifactsOrigin.server,
	};

	await init(anonAadhaarInitArgs);

	for (let i = 0; i < 3; i++) {
		for (let j = 0; j < 2; j++) {
			await generateProof(i, j, testData[i], certificate);
		}
	}
}

async function generateProof(
	id: number,
	inner_id: number,
	testQRData: string,
	certificate: string
) {
	const _signal = id == 2 && inner_id == 1 ? calldataHash : signal;

	const args = await generateArgs({
		qrData: testQRData,
		certificateFile: certificate,
		nullifierSeed: nullifierSeed,
		signal: _signal, // user op hash
	});

	const anonAadhaarCore = await prove(args);
	const anonAadhaarProof = anonAadhaarCore.proof;
	const packedGroth16Proof = packGroth16Proof(anonAadhaarProof.groth16Proof);

	const encoder = ethers.AbiCoder.defaultAbiCoder();
	const proofData = encoder.encode(
		["uint", "uint", "uint[4]", "uint[8]"],
		[
			BigInt(nullifierSeed),
			Number(anonAadhaarCore?.proof.timestamp),
			[
				anonAadhaarProof.ageAbove18,
				anonAadhaarProof.gender,
				anonAadhaarProof.pincode,
				anonAadhaarProof.state,
			],
			packedGroth16Proof,
		]
	);

	console.log("anonAadhaarProof.nullifier: ", anonAadhaarProof.nullifier);
	console.log(`proofData ${id}: `, proofData);
}

generateProofs();
