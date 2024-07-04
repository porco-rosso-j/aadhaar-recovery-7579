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

const signal = "1";
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
		// for (let j = 0; j < 2; j++) {
		await generateProof(i, testData[i], certificate);
		// }
	}
}

async function generateProof(
	id: number,
	testQRData: string,
	certificate: string
) {
	const args = await generateArgs({
		qrData: testQRData,
		certificateFile: certificate,
		nullifierSeed: nullifierSeed,
		signal: signal, // user op hash
	});

	const anonAadhaarCore = await prove(args);
	const anonAadhaarProof = anonAadhaarCore.proof;
	const packedGroth16Proof = packGroth16Proof(anonAadhaarProof.groth16Proof);
	console.log("anonAadhaarProof.nullifier: ", anonAadhaarProof.nullifier);

	const encoder = ethers.AbiCoder.defaultAbiCoder();
	const proofData = encoder.encode(
		["uint", "uint", "uint", "uint[4]", "uint[8]"],
		[
			BigInt(nullifierSeed),
			Number(anonAadhaarCore?.proof.timestamp),
			BigInt(signal), // insert userOpHash into signature
			[
				anonAadhaarProof.ageAbove18,
				anonAadhaarProof.gender,
				anonAadhaarProof.pincode,
				anonAadhaarProof.state,
			],
			packedGroth16Proof,
		]
	);

	console.log(`proofData ${id}: `, proofData);
}

generateProofs();
