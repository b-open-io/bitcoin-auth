import { PrivateKey, PublicKey, SymmetricKey, Utils } from "@bsv/sdk";

export interface EncryptedPayload {
	ephemeralPub: string;
	ciphertext: string;
}

export function encryptPayload(serverPubKeyHex: string, plaintext: string): EncryptedPayload {
	if (!serverPubKeyHex || typeof serverPubKeyHex !== "string") {
		throw new Error("Invalid server public key");
	}

	let serverPubKey: PublicKey;
	try {
		serverPubKey = PublicKey.fromString(serverPubKeyHex);
	} catch {
		throw new Error("Invalid server public key format");
	}

	const ephemeralPriv = PrivateKey.fromRandom();
	const sharedPoint = ephemeralPriv.deriveSharedSecret(serverPubKey);
	const symmetricKey = new SymmetricKey(sharedPoint.encode(true).slice(1));

	return {
		ephemeralPub: ephemeralPriv.toPublicKey().toString(),
		ciphertext: symmetricKey.encrypt(Utils.toArray(plaintext, "utf8"), "hex") as string,
	};
}

export function decryptPayload(serverPrivKey: PrivateKey, encrypted: EncryptedPayload): string {
	if (!encrypted?.ephemeralPub || typeof encrypted.ephemeralPub !== "string") {
		throw new Error("Invalid encrypted payload: missing ephemeralPub");
	}
	if (!encrypted?.ciphertext || typeof encrypted.ciphertext !== "string") {
		throw new Error("Invalid encrypted payload: missing ciphertext");
	}

	const ephemeralPub = PublicKey.fromString(encrypted.ephemeralPub);
	const sharedPoint = serverPrivKey.deriveSharedSecret(ephemeralPub);
	const symmetricKey = new SymmetricKey(sharedPoint.encode(true).slice(1));

	return symmetricKey.decrypt(Utils.toArray(encrypted.ciphertext, "hex"), "utf8") as string;
}
