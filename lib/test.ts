import test from "node:test";
import assert from "node:assert";

import PasswordBuilder from ".";
import isAllowedValue from "./utils/is-allowed-value.util";
import safePasswordConfigurationAdapter from "./adapter/safe-password-configuration.adapter";
import { CommonPasswordConfiguration } from "./interfaces";
import defaultPasswordConfiguration from "./default-password.config";

import { PSBErrors } from "./enum/Errors.enum";

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
        "B5huQROTsAubI0Foe3.86e54b7687254f3a9d3413d3254dbd995d8ca71cc6679c4e592bf55f653c76897154ea9763e7b5c74d55dec560a528c88b60c2a2985b9ad8130bfd53a89acb5b";

      const hashedPassword = PasswordBuilder.hash(password, salt);

      assert.strictEqual(hashedPassword, expectedHash);
    }
  );

  await t.test(
    "PasswordBuilder.hash() should return a string hashed password, with a specific salt hash separator",
    async (t) => {
      const password = "password_123";
      const salt = "spidermanvsbatman";
      const saltHashSeparator = "||";

      const expectedHash = `${salt}${saltHashSeparator}RWbTOAtwP9e55sp0U+3/U7auSjjGAHqK7q0uk77Swbk=`;

      const hashedPassword = PasswordBuilder.hash(password, salt, {
        hashAlgorithm: "sha256",
        hashDigest: "base64",
        inSeparator: saltHashSeparator,
      });

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
        assert.strictEqual(
          (error as Error).message,
          PSBErrors.ConfigurationMustBeAnObjectOrUndefined
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

test("PasswordBuilder : Utilities & Adapters", async (t) => {
  await t.test(
    "Utils isAllowedValue : Should return true if value is present in the array",
    async (t) => {
      const value = "value2";

      const allowedValues = ["value0", "feuneu", "value2", "gazo", "zed"];

      const isAllowed = isAllowedValue(value, allowedValues);

      assert.strictEqual(isAllowed, true);
    }
  );

  await t.test(
    "Utils isAllowedValue : Should return false if value is not present in the array",
    async (t) => {
      const value = "normalement_impossible_a_trouver";

      const allowedValues = ["ou", "pas", "du", "tout", "on", "sait", "jamais"];

      const isAllowed = isAllowedValue(value, allowedValues);

      assert.strictEqual(isAllowed, false);
    }
  );

  await t.test(
    "Adapters safePasswordConfigurationAdapter : Should return a valid configuration object",
    async (t) => {
      const configuration: CommonPasswordConfiguration = {
        hashAlgorithm: "sha256",
        hashDigest: "base64url",
        inSeparator: "!",
      };

      const adaptedConfiguration =
        safePasswordConfigurationAdapter(configuration);

      assert.strictEqual(adaptedConfiguration.hashAlgorithm, "sha256");
      assert.strictEqual(adaptedConfiguration.hashDigest, "base64url");
      assert.strictEqual(adaptedConfiguration.inSeparator, "!");
    }
  );

  await t.test(
    "Adapters safePasswordConfigurationAdapter : Should return a valid configuration object if configuration is equal to the default configuration",
    async (t) => {
      const adaptedConfiguration = safePasswordConfigurationAdapter(
        defaultPasswordConfiguration
      );

      assert.strictEqual(
        adaptedConfiguration.hashAlgorithm,
        defaultPasswordConfiguration.hashAlgorithm
      );
      assert.strictEqual(
        adaptedConfiguration.hashDigest,
        defaultPasswordConfiguration.hashDigest
      );
      assert.strictEqual(
        adaptedConfiguration.inSeparator,
        defaultPasswordConfiguration.inSeparator
      );
    }
  );

  await t.test(
    "Adapters safePasswordConfigurationAdapter : Should return a valid configuration object and strictly equal to the default configuration",
    async (t) => {
      const configuration = undefined;

      const adaptedConfiguration =
        safePasswordConfigurationAdapter(configuration);

      assert.strictEqual(adaptedConfiguration, defaultPasswordConfiguration);
    }
  );

  await t.test(
    "Adapters safePasswordConfigurationAdapter : Should return an error if the configuration is not an object.",
    async (t) => {
      try {
        const configuration = [] as unknown as CommonPasswordConfiguration;

        safePasswordConfigurationAdapter(configuration);
      } catch (error: unknown) {
        assert.strictEqual(
          (error as Error).message,
          PSBErrors.ConfigurationMustBeAnObjectOrUndefined
        );
      }
    }
  );

  await t.test(
    "Adapters safePasswordConfigurationAdapter : Should return a valid configuration object and strictly equal to the default configuration, if the configuration values are not allowed.",
    async (t) => {
      const configuration = {
        hashAlgorithm: "_unknown_hash_algorithm_",
        hashDigest: "_unknown_hash_digest_",
        inSeparator: [999], // Invalid separator (only string are allowed)
      } as unknown as CommonPasswordConfiguration;

      const adaptedConfiguration =
        safePasswordConfigurationAdapter(configuration);

      assert.strictEqual(
        adaptedConfiguration.hashAlgorithm,
        defaultPasswordConfiguration.hashAlgorithm
      );
      assert.strictEqual(
        adaptedConfiguration.hashDigest,
        defaultPasswordConfiguration.hashDigest
      );
      assert.strictEqual(
        adaptedConfiguration.inSeparator,
        defaultPasswordConfiguration.inSeparator
      );
    }
  );
});
