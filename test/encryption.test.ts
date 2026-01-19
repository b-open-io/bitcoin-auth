import { describe, expect, it } from "bun:test";
import { PrivateKey } from "@bsv/sdk";
import { decryptPayload, encryptPayload, type EncryptedPayload } from "../src/encryption";

describe("Encryption Utilities", () => {
	describe("encryptPayload", () => {
		it("should encrypt a simple string", () => {
			const serverPrivKey = PrivateKey.fromRandom();
			const serverPubKeyHex = serverPrivKey.toPublicKey().toString();

			const plaintext = "Hello, World!";
			const encrypted = encryptPayload(serverPubKeyHex, plaintext);

			expect(encrypted.ephemeralPub).toBeDefined();
			expect(encrypted.ephemeralPub.length).toBe(66); // Compressed pubkey
			expect(encrypted.ciphertext).toBeDefined();
			expect(encrypted.ciphertext.length).toBeGreaterThan(0);
		});

		it("should encrypt JSON data", () => {
			const serverPrivKey = PrivateKey.fromRandom();
			const serverPubKeyHex = serverPrivKey.toPublicKey().toString();

			const data = { password: "secret123", host: "example.com" };
			const plaintext = JSON.stringify(data);
			const encrypted = encryptPayload(serverPubKeyHex, plaintext);

			expect(encrypted.ephemeralPub).toBeDefined();
			expect(encrypted.ciphertext).toBeDefined();
		});

		it("should produce different ciphertext for same plaintext (forward secrecy)", () => {
			const serverPrivKey = PrivateKey.fromRandom();
			const serverPubKeyHex = serverPrivKey.toPublicKey().toString();

			const plaintext = "same message";
			const encrypted1 = encryptPayload(serverPubKeyHex, plaintext);
			const encrypted2 = encryptPayload(serverPubKeyHex, plaintext);

			// Different ephemeral keys should produce different ciphertext
			expect(encrypted1.ephemeralPub).not.toBe(encrypted2.ephemeralPub);
			expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext);
		});

		it("should throw on invalid server public key", () => {
			expect(() => encryptPayload("", "test")).toThrow("Invalid server public key");
			expect(() => encryptPayload("invalid", "test")).toThrow("Invalid server public key format");
			expect(() => encryptPayload("0123456789", "test")).toThrow("Invalid server public key format");
		});

		it("should handle empty plaintext", () => {
			const serverPrivKey = PrivateKey.fromRandom();
			const serverPubKeyHex = serverPrivKey.toPublicKey().toString();

			const encrypted = encryptPayload(serverPubKeyHex, "");
			expect(encrypted.ciphertext).toBeDefined();
		});

		it("should handle unicode characters", () => {
			const serverPrivKey = PrivateKey.fromRandom();
			const serverPubKeyHex = serverPrivKey.toPublicKey().toString();

			const plaintext = "Hello, \u4e16\u754c! \u{1F600}"; // Hello, 世界! 😀
			const encrypted = encryptPayload(serverPubKeyHex, plaintext);

			expect(encrypted.ciphertext).toBeDefined();
		});
	});

	describe("decryptPayload", () => {
		it("should decrypt what was encrypted", () => {
			const serverPrivKey = PrivateKey.fromRandom();
			const serverPubKeyHex = serverPrivKey.toPublicKey().toString();

			const plaintext = "Hello, World!";
			const encrypted = encryptPayload(serverPubKeyHex, plaintext);
			const decrypted = decryptPayload(serverPrivKey, encrypted);

			expect(decrypted).toBe(plaintext);
		});

		it("should decrypt JSON data correctly", () => {
			const serverPrivKey = PrivateKey.fromRandom();
			const serverPubKeyHex = serverPrivKey.toPublicKey().toString();

			const data = { password: "secret123", host: "example.com", scopes: ["read", "write"] };
			const plaintext = JSON.stringify(data);
			const encrypted = encryptPayload(serverPubKeyHex, plaintext);
			const decrypted = decryptPayload(serverPrivKey, encrypted);

			expect(decrypted).toBe(plaintext);
			expect(JSON.parse(decrypted)).toEqual(data);
		});

		it("should decrypt empty string", () => {
			const serverPrivKey = PrivateKey.fromRandom();
			const serverPubKeyHex = serverPrivKey.toPublicKey().toString();

			const encrypted = encryptPayload(serverPubKeyHex, "");
			const decrypted = decryptPayload(serverPrivKey, encrypted);

			expect(decrypted).toBe("");
		});

		it("should decrypt unicode characters", () => {
			const serverPrivKey = PrivateKey.fromRandom();
			const serverPubKeyHex = serverPrivKey.toPublicKey().toString();

			const plaintext = "Hello, \u4e16\u754c! \u{1F600}";
			const encrypted = encryptPayload(serverPubKeyHex, plaintext);
			const decrypted = decryptPayload(serverPrivKey, encrypted);

			expect(decrypted).toBe(plaintext);
		});

		it("should throw on missing ephemeralPub", () => {
			const serverPrivKey = PrivateKey.fromRandom();
			const malformed = { ciphertext: "abc123" } as EncryptedPayload;

			expect(() => decryptPayload(serverPrivKey, malformed)).toThrow(
				"Invalid encrypted payload: missing ephemeralPub",
			);
		});

		it("should throw on missing ciphertext", () => {
			const serverPrivKey = PrivateKey.fromRandom();
			const malformed = { ephemeralPub: serverPrivKey.toPublicKey().toString() } as EncryptedPayload;

			expect(() => decryptPayload(serverPrivKey, malformed)).toThrow(
				"Invalid encrypted payload: missing ciphertext",
			);
		});

		it("should throw on invalid ephemeralPub format", () => {
			const serverPrivKey = PrivateKey.fromRandom();
			const malformed: EncryptedPayload = {
				ephemeralPub: "invalid_pubkey",
				ciphertext: "abc123",
			};

			expect(() => decryptPayload(serverPrivKey, malformed)).toThrow();
		});

		it("should fail with wrong private key", () => {
			const serverPrivKey = PrivateKey.fromRandom();
			const wrongPrivKey = PrivateKey.fromRandom();
			const serverPubKeyHex = serverPrivKey.toPublicKey().toString();

			const plaintext = "secret message";
			const encrypted = encryptPayload(serverPubKeyHex, plaintext);

			// Using wrong key should fail (GCM auth tag verification)
			expect(() => decryptPayload(wrongPrivKey, encrypted)).toThrow();
		});

		it("should fail with tampered ciphertext", () => {
			const serverPrivKey = PrivateKey.fromRandom();
			const serverPubKeyHex = serverPrivKey.toPublicKey().toString();

			const plaintext = "secret message";
			const encrypted = encryptPayload(serverPubKeyHex, plaintext);

			// Tamper with ciphertext
			const tampered: EncryptedPayload = {
				...encrypted,
				ciphertext: encrypted.ciphertext.slice(0, -2) + "00",
			};

			// GCM should detect tampering
			expect(() => decryptPayload(serverPrivKey, tampered)).toThrow();
		});

		it("should fail with tampered ephemeralPub", () => {
			const serverPrivKey = PrivateKey.fromRandom();
			const serverPubKeyHex = serverPrivKey.toPublicKey().toString();
			const differentKey = PrivateKey.fromRandom().toPublicKey().toString();

			const plaintext = "secret message";
			const encrypted = encryptPayload(serverPubKeyHex, plaintext);

			// Replace ephemeral pub with different key
			const tampered: EncryptedPayload = {
				...encrypted,
				ephemeralPub: differentKey,
			};

			// Should fail because derived shared secret will be wrong
			expect(() => decryptPayload(serverPrivKey, tampered)).toThrow();
		});
	});

	describe("round-trip with various payloads", () => {
		const testCases = [
			{ name: "short string", payload: "hi" },
			{ name: "medium string", payload: "The quick brown fox jumps over the lazy dog." },
			{
				name: "long string",
				payload: "A".repeat(10000),
			},
			{ name: "numbers in JSON", payload: JSON.stringify({ value: 12345.6789 }) },
			{ name: "boolean in JSON", payload: JSON.stringify({ active: true, disabled: false }) },
			{ name: "null in JSON", payload: JSON.stringify({ value: null }) },
			{ name: "array in JSON", payload: JSON.stringify([1, 2, 3, "four", { five: 5 }]) },
			{ name: "nested object", payload: JSON.stringify({ a: { b: { c: { d: "deep" } } } }) },
			{ name: "special chars", payload: '<script>alert("xss")</script>' },
			{ name: "newlines", payload: "line1\nline2\r\nline3" },
			{ name: "tabs", payload: "col1\tcol2\tcol3" },
		];

		for (const { name, payload } of testCases) {
			it(`should round-trip: ${name}`, () => {
				const serverPrivKey = PrivateKey.fromRandom();
				const serverPubKeyHex = serverPrivKey.toPublicKey().toString();

				const encrypted = encryptPayload(serverPubKeyHex, payload);
				const decrypted = decryptPayload(serverPrivKey, encrypted);

				expect(decrypted).toBe(payload);
			});
		}
	});
});
