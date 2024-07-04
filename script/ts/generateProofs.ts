import { copmuteUserNullifier } from "./computeNullifier";
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

const proofLen = 3;
const signal = "1";
const nullifierSeed = 1234;
const testPublicKeyHash =
	"15134874015316324267425466444584014077184337590635665158241104437045239495873";

type QrData = {
	testQRData: string;
};

async function generateProofs() {
	let testQRDataArray: string[] = [];
	for (let i = 0; i < proofLen; i++) {
		const privateKeyResponse = await fetch(
			"https://nodejs-serverless-function-express-eight-iota.vercel.app/api/get-fresh-qr"
		);

		if (!privateKeyResponse.ok) {
			throw new Error("Something went wrong when fetching new QR code");
		}
		const newQrData = (await privateKeyResponse.json()) as QrData;

		testQRDataArray.push(newQrData.testQRData);

		// console.log("testQRData: ", newQrData.testQRData);
		// console.log(
		// 	`nullifier: ${i}: `,
		// 	await copmuteUserNullifier(nullifierSeed, newQrData.testQRData)
		// );
	}

	const certificate = fs
		.readFileSync(__dirname + "/testCertificate.pem")
		.toString();
	// console.log("certificate: ", certificate);

	const anonAadhaarInitArgs: InitArgs = {
		wasmURL: artifactUrls.v2.wasm,
		zkeyURL: artifactUrls.v2.zkey,
		vkeyURL: artifactUrls.v2.vk,
		artifactsOrigin: ArtifactsOrigin.server,
	};

	await init(anonAadhaarInitArgs);

	for (let i = 0; i < proofLen; i++) {
		await generateProof(i, testQRDataArray[i], certificate);
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

	// console.log(
	// 	`nullifier: ${id}: `,
	// 	await copmuteUserNullifier(nullifierSeed, testQRData)
	// );
}

generateProofs();
