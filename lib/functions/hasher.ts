import { createHmac } from "node:crypto";
import type { Hash, SafePasswordConfiguration } from "../types";

/**
 * This function is used to hash a password using the provided salt and configuration.
 * @param password
 * @param salt
 * @param configuration
 * @returns string
 */
export default function hasher(
  password: string,
  salt: string,
  configuration: SafePasswordConfiguration
): Hash["hashedPassword"] {
  const hash = createHmac(configuration.hashAlgorithm, salt);
  hash.update(password);
  const value = hash.digest(configuration.hashDigest);

  return `${salt}${configuration.inSeparator}${value}`;
}
