import { PrivateKey, PublicKey, SymmetricKey, Utils } from "@bsv/sdk";

/**
 * Encrypt a message for a counterparty using ECDH + AES-256-GCM.
 *
 * Both parties derive the same shared secret:
 * - Sender: senderPrivKey * recipientPubKey
 * - Recipient: recipientPrivKey * senderPubKey
 *
 * @param senderPrivKey - Sender's private key
 * @param recipientPubKey - Recipient's public key (hex string)
 * @param plaintext - Message to encrypt
 * @returns Ciphertext (hex string)
 */
export function encrypt(
	senderPrivKey: PrivateKey,
	recipientPubKey: string,
	plaintext: string,
): string {
	const recipientPub = PublicKey.fromString(recipientPubKey);
	const sharedPoint = senderPrivKey.deriveSharedSecret(recipientPub);
	const symmetricKey = new SymmetricKey(sharedPoint.encode(true).slice(1));
	return symmetricKey.encrypt(Utils.toArray(plaintext, "utf8"), "hex") as string;
}

/**
 * Decrypt a message from a counterparty using ECDH + AES-256-GCM.
 *
 * @param recipientPrivKey - Recipient's private key
 * @param senderPubKey - Sender's public key (hex string)
 * @param ciphertext - Encrypted message (hex string)
 * @returns Decrypted plaintext
 */
export function decrypt(
	recipientPrivKey: PrivateKey,
	senderPubKey: string,
	ciphertext: string,
): string {
	const senderPub = PublicKey.fromString(senderPubKey);
	const sharedPoint = recipientPrivKey.deriveSharedSecret(senderPub);
	const symmetricKey = new SymmetricKey(sharedPoint.encode(true).slice(1));
	return symmetricKey.decrypt(Utils.toArray(ciphertext, "hex"), "utf8") as string;
}
