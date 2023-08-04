import test from "node:test";
import assert from "node:assert";

import PasswordBuilder from ".";

test("PasswordBuilder.hash()", async (t) => {
  await t.test(
    "PasswordBuilder.hash() should return a string hashed password",
    async (t) => {
      const password = "password_123";
      const salt = "spidermanvsbatman";

      const expectedHash =
        "spidermanvsbatman.RWbTOAtwP9e55sp0U+3/U7auSjjGAHqK7q0uk77Swbk=";

      const hashedPassword = PasswordBuilder.hash(password, salt, {
        hashAlgorithm: "sha256",
        hashDigest: "base64",
      });

      assert.strictEqual(hashedPassword, expectedHash);
    }
  );

  await t.test(
    "PasswordBuilder.hash() should return a string hashed password (complex password with special characters and default configuration)",
    async (t) => {
      const password = "hh_2jHSBrs<vXPZX3]MA%jk{bY7[q^$^!d";
      const salt = "B5huQROTsAubI0Foe3";

      const expectedHash =
        "B5huQROTsAubI0Foe3.C63xQ1CIqI7k5J80I2FW8yd+22erTSBZ0CFHvFWGHug=";

      const hashedPassword = PasswordBuilder.hash(password, salt);

      assert.strictEqual(hashedPassword, expectedHash);
    }
  );

  await t.test(
    "PasswordBuilder.hash() should throw an error if password is null",
    async (t) => {
      try {
        const password = null as unknown as string;
        const salt = null as unknown as string;

        PasswordBuilder.hash(password, salt);
      } catch (error: unknown) {
        assert.strictEqual(
          (error as Error).message,
          "Must Provide Password and salt values"
        );
      }
    }
  );

  await t.test(
    "PasswordBuilder.hash() should throw an error if password is not a string",
    async (t) => {
      try {
        const password = 123 as unknown as string;
        const salt = "hello";

        PasswordBuilder.hash(password, salt);
      } catch (error: unknown) {
        assert.strictEqual(
          (error as Error).message,
          "password must be a string and salt must either be a salt string or a number of rounds"
        );
      }
    }
  );

  await t.test(
    "PasswordBuilder.hash() should throw an error if salt is not a string",
    async (t) => {
      try {
        const password = "hello";
        const salt = 123 as unknown as string;

        PasswordBuilder.hash(password, salt);
      } catch (error: unknown) {
        assert.strictEqual(
          (error as Error).message,
          "password must be a string and salt must either be a salt string or a number of rounds"
        );
      }
    }
  );
});

test("PasswordBuilder.verify()", async (t) => {
  await t.test(
    "PasswordBuilder.verify() should return true if password is valid",
    async (t) => {
      const password = "password_456";

      const expectedHash =
        "gothamcity.74feb8fa77b7651d3aca2abc075c60d55d5d7f8b053d1b06dc5fc725cf4651acf7ce8adcf2fb392deb4554c967af15e54294892926aed5fed6a2ab5bec66419d";

      const isPasswordValid = PasswordBuilder.verify(password, expectedHash, {
        hashAlgorithm: "sha512",
        hashDigest: "hex",
      });

      assert.strictEqual(isPasswordValid, true);
    }
  );

  await t.test(
    "PasswordBuilder.verify() should return false if password is invalid",
    async (t) => {
      const password = "password_456";

      const expectedHash = "invalid_hash_value";

      const isPasswordValid = PasswordBuilder.verify(password, expectedHash, {
        hashAlgorithm: "sha512",
        hashDigest: "hex",
      });

      assert.strictEqual(isPasswordValid, false);
    }
  );

  await t.test(
    "PasswordBuilder.verify() should throw an error if password is null",
    async (t) => {
      try {
        const password = "password";

        const hashedPassword = null as unknown as string;

        PasswordBuilder.verify(password, hashedPassword);
      } catch (error: unknown) {
        assert.strictEqual(
          (error as Error).message,
          "Must Provide hashedPassword"
        );
      }
    }
  );

  await t.test(
    "PasswordBuilder.verify() should throw an error if password is not a string and hash configuration is an object",
    async (t) => {
      try {
        const password = 123 as unknown as string;

        const hashedPassword = "hashedPassword";

        const hashConfig = "hashConfig" as unknown as {};

        PasswordBuilder.verify(password, hashedPassword, hashConfig);
      } catch (error: unknown) {
        console.log("error", error);
        assert.strictEqual(
          (error as Error).message,
          "password must be a String and hash must be an Object of { salt, hashedPassword }"
        );
      }
    }
  );
});

test("PasswordBuilder.generateSalt()", async (t) => {
  await t.test(
    "PasswordBuilder.generateSalt() should return a string salt",
    async (t) => {
      const salt = PasswordBuilder.generateSalt();

      assert.strictEqual(typeof salt, "string");
    }
  );

  await t.test(
    "PasswordBuilder.generateSalt() should throw an error if rounds is not a number",
    async (t) => {
      try {
        const rounds = "rounds" as unknown as number;

        PasswordBuilder.generateSalt(rounds);
      } catch (error: unknown) {
        assert.strictEqual(
          (error as Error).message,
          "rounds param must be a number"
        );
      }
    }
  );

  await t.test(
    "PasswordBuilder.generateSalt() should throw an error if rounds is less than 0",
    async (t) => {
      try {
        const rounds = -1;

        PasswordBuilder.generateSalt(rounds);
      } catch (error: unknown) {
        assert.strictEqual(
          (error as Error).message,
          "rounds param must be greater than 0"
        );
      }
    }
  );
});
