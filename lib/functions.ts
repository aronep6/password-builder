import { createHmac, randomBytes } from "node:crypto";
import safeCommonPasswordConfigurationAdapter from "./adapter/safe-password-configuration.adapter";
import type {
  CommonPasswordConfiguration,
  Hash,
  SafePasswordConfiguration,
} from "./types";

/**
 * This is the default number of rounds used to generate a salt (by default 11).
 */
const DEFAULT_SALT_ROUNDS: number = 11;

/**
 * This function is used to hash a password using the provided salt and configuration.
 * @param password
 * @param salt
 * @param configuration
 * @returns string
 */
function hasher(
  password: string,
  salt: string,
  configuration: SafePasswordConfiguration
): Hash["hashedPassword"] {
  const hash = createHmac(configuration.hashAlgorithm, salt);
  hash.update(password);
  const value = hash.digest(configuration.hashDigest);

  return `${salt}${configuration.inSeparator}${value}`;
}

/**
 * This function is used to hash a password using the provided salt and configuration, you can provide a configuration to override the default configuration.
 * @param password
 * @param salt
 * @param configuration
 * @returns string
 */
export function hash(
  password: string,
  salt: string,
  configuration?: CommonPasswordConfiguration | SafePasswordConfiguration
): string {
  if (password == null || salt == null) {
    throw new Error("Must Provide Password and salt values");
  }
  if (typeof password !== "string" || typeof salt !== "string") {
    throw new Error(
      "password must be a string and salt must either be a salt string or a number of rounds"
    );
  }

  const safeConfiguration: SafePasswordConfiguration =
    safeCommonPasswordConfigurationAdapter(configuration);

  return hasher(password, salt, safeConfiguration);
}

/**
 * This function is used to generate a salt for hashing a password, the salt is used to add complexity to the password hash.
 * @param rounds
 * @returns string
 */
export function generateSalt(rounds: number = DEFAULT_SALT_ROUNDS): string {
  if (typeof rounds !== "number") {
    throw new Error("rounds param must be a number");
  }

  if (rounds < 0) {
    throw new Error("rounds param must be greater than 0");
  }

  if (rounds > 13) {
    console.warn(
      "[PasswordBuilder]: Consider setting rounds param to 13 or lower for production, as this may cause high CPU usage."
    );
  }

  const salt = randomBytes(Math.ceil(rounds / 2)).toString("hex");

  return salt.slice(0, rounds);
}

/**
 * This function is used to verify a password against a hashed password using the configuration provided.
 * @param password
 * @param hashedPassword
 * @param configuration
 * @returns boolean
 */
export function verify(
  password: string,
  hashedPassword: string,
  configuration?: CommonPasswordConfiguration | SafePasswordConfiguration
): boolean {
  if (hashedPassword == null) {
    throw new Error("Must Provide hashedPassword");
  }

  const safeConfiguration: SafePasswordConfiguration =
    safeCommonPasswordConfigurationAdapter(configuration);

  const subPass: string[] = hashedPassword.split(safeConfiguration.inSeparator);

  const passwordHashConfiguration: Hash = {
    salt: subPass[0],
    hashedPassword: subPass[1],
  };

  if (
    typeof password !== "string" ||
    typeof passwordHashConfiguration !== "object"
  ) {
    throw new Error(
      "password must be a String and hash must be an Object of { salt, hashedPassword }"
    );
  }

  const hash: string = hasher(
    password,
    passwordHashConfiguration.salt,
    safeConfiguration
  );

  if (password == null || hash == null) {
    throw new Error("password and hash is required to compare");
  }

  if (hash === hashedPassword && password.length > 0 && hash.length > 0) {
    return true;
  }
  return false;
}
