import {
  CommonPasswordConfiguration,
  SafePasswordConfiguration,
} from "../types";
import hasher from "./hasher";
import safePasswordConfigurationAdapter from "../adapter/safe-password-configuration.adapter";

/**
 * This function is used to hash a password using the provided salt and configuration, you can provide a configuration to override the default configuration.
 * @param password
 * @param salt
 * @param configuration
 * @returns string
 */
export default function hash(
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
    safePasswordConfigurationAdapter(configuration);

  return hasher(password, salt, safeConfiguration);
}
