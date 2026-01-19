import { describe, expect, it } from "bun:test";
import { PrivateKey } from "@bsv/sdk";
import { decrypt, encrypt } from "../src/encryption";

describe("Encryption", () => {
	it("should encrypt and decrypt between two parties", () => {
		const alice = PrivateKey.fromRandom();
		const bob = PrivateKey.fromRandom();

		const plaintext = "Hello, Bob!";
		const ciphertext = encrypt(alice, bob.toPublicKey().toString(), plaintext);
		const decrypted = decrypt(bob, alice.toPublicKey().toString(), ciphertext);

		expect(decrypted).toBe(plaintext);
	});

	it("should produce same shared secret from both sides", () => {
		const alice = PrivateKey.fromRandom();
		const bob = PrivateKey.fromRandom();

		const plaintext = "Bidirectional test";

		// Alice encrypts to Bob
		const ciphertext1 = encrypt(alice, bob.toPublicKey().toString(), plaintext);
		const decrypted1 = decrypt(bob, alice.toPublicKey().toString(), ciphertext1);

		// Bob encrypts to Alice
		const ciphertext2 = encrypt(bob, alice.toPublicKey().toString(), plaintext);
		const decrypted2 = decrypt(alice, bob.toPublicKey().toString(), ciphertext2);

		expect(decrypted1).toBe(plaintext);
		expect(decrypted2).toBe(plaintext);
	});

	it("should fail with wrong recipient key", () => {
		const alice = PrivateKey.fromRandom();
		const bob = PrivateKey.fromRandom();
		const eve = PrivateKey.fromRandom();

		const ciphertext = encrypt(alice, bob.toPublicKey().toString(), "secret");

		// Eve tries to decrypt with wrong key
		expect(() => decrypt(eve, alice.toPublicKey().toString(), ciphertext)).toThrow();
	});

	it("should fail with wrong sender key", () => {
		const alice = PrivateKey.fromRandom();
		const bob = PrivateKey.fromRandom();
		const eve = PrivateKey.fromRandom();

		const ciphertext = encrypt(alice, bob.toPublicKey().toString(), "secret");

		// Bob uses wrong sender pubkey
		expect(() => decrypt(bob, eve.toPublicKey().toString(), ciphertext)).toThrow();
	});

	it("should handle empty string", () => {
		const alice = PrivateKey.fromRandom();
		const bob = PrivateKey.fromRandom();

		const ciphertext = encrypt(alice, bob.toPublicKey().toString(), "");
		const decrypted = decrypt(bob, alice.toPublicKey().toString(), ciphertext);

		expect(decrypted).toBe("");
	});

	it("should handle unicode", () => {
		const alice = PrivateKey.fromRandom();
		const bob = PrivateKey.fromRandom();

		const plaintext = "Hello, 世界! 🚀";
		const ciphertext = encrypt(alice, bob.toPublicKey().toString(), plaintext);
		const decrypted = decrypt(bob, alice.toPublicKey().toString(), ciphertext);

		expect(decrypted).toBe(plaintext);
	});

	it("should handle JSON data", () => {
		const alice = PrivateKey.fromRandom();
		const bob = PrivateKey.fromRandom();

		const data = { password: "secret123", host: "example.com" };
		const plaintext = JSON.stringify(data);
		const ciphertext = encrypt(alice, bob.toPublicKey().toString(), plaintext);
		const decrypted = decrypt(bob, alice.toPublicKey().toString(), ciphertext);

		expect(JSON.parse(decrypted)).toEqual(data);
	});

	it("should produce different ciphertext for same plaintext (random IV)", () => {
		const alice = PrivateKey.fromRandom();
		const bob = PrivateKey.fromRandom();

		const plaintext = "same message";
		const ciphertext1 = encrypt(alice, bob.toPublicKey().toString(), plaintext);
		const ciphertext2 = encrypt(alice, bob.toPublicKey().toString(), plaintext);

		// Different IVs produce different ciphertext
		expect(ciphertext1).not.toBe(ciphertext2);

		// But both decrypt correctly
		expect(decrypt(bob, alice.toPublicKey().toString(), ciphertext1)).toBe(plaintext);
		expect(decrypt(bob, alice.toPublicKey().toString(), ciphertext2)).toBe(plaintext);
	});

	it("should fail with tampered ciphertext", () => {
		const alice = PrivateKey.fromRandom();
		const bob = PrivateKey.fromRandom();

		const ciphertext = encrypt(alice, bob.toPublicKey().toString(), "secret");
		const tampered = ciphertext.slice(0, -2) + "00";

		expect(() => decrypt(bob, alice.toPublicKey().toString(), tampered)).toThrow();
	});
});
