import safePasswordConfigurationAdapter from "../adapter/safe-password-configuration.adapter";
import type {
  CommonPasswordConfiguration,
  Hash,
  SafePasswordConfiguration,
} from "../types";
import hasher from "./hasher";

/**
 * This function is used to verify a password against a hashed password using the configuration provided.
 * @param password
 * @param hashedPassword
 * @param configuration
 * @returns boolean
 */
export default function verify(
  password: string,
  hashedPassword: string,
  configuration?: CommonPasswordConfiguration | SafePasswordConfiguration
): boolean {
  if (hashedPassword == null) {
    throw new Error("Must Provide hashedPassword");
  }

  const safeConfiguration: SafePasswordConfiguration =
    safePasswordConfigurationAdapter(configuration);

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
