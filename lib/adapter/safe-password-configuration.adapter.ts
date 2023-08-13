import type {
  CommonPasswordConfiguration,
  SafePasswordConfiguration,
} from "../interfaces";

import allowedHashAlgorithms from "../constants/allowed-hash-algorithms";
import isAllowedValue from "../utils/is-allowed-value.util";
import allowedHashDigests from "../constants/allowed-hash-digests";
import defaultPasswordConfiguration from "../default-password.config";

import { PSBWarnings } from "../enum/Warnings.enum";
import { PSBErrors } from "../enum/Errors.enum";

const safePasswordConfigurationAdapter = (
  configuration?: CommonPasswordConfiguration
): SafePasswordConfiguration => {
  if (!configuration) {
    console.log(PSBWarnings.NoConfigurationProvided);
    return defaultPasswordConfiguration;
  }

  const configurationIsArray = Array.isArray(configuration);

  if (
    (typeof configuration !== "object" &&
      typeof configuration !== "undefined") ||
    configurationIsArray
  ) {
    throw new Error(PSBErrors.ConfigurationMustBeAnObjectOrUndefined);
  }

  if (
    typeof configuration.hashAlgorithm !== "string" ||
    typeof configuration.hashDigest !== "string"
  ) {
    throw new Error(PSBErrors.HashAlgorithmAndHashDigestMustBeStrings);
  }

  const hashAlgorithmIsValid = isAllowedValue(
    configuration.hashAlgorithm,
    allowedHashAlgorithms
  );

  const hashDigestIsValid = isAllowedValue(
    configuration.hashDigest,
    allowedHashDigests
  );

  const inSeparatorValue =
    configuration.inSeparator && typeof configuration.inSeparator === "string"
      ? configuration.inSeparator
      : defaultPasswordConfiguration.inSeparator;

  if (!hashAlgorithmIsValid || !hashDigestIsValid) {
    console.warn(
      PSBWarnings.OneOrMoreOfTheProvidedHashConfigurationValuesSeemToBeInvalid
    );
  }

  return {
    hashAlgorithm: hashAlgorithmIsValid
      ? configuration.hashAlgorithm
      : defaultPasswordConfiguration.hashAlgorithm,
    hashDigest: hashDigestIsValid
      ? configuration.hashDigest
      : defaultPasswordConfiguration.hashDigest,
    inSeparator: inSeparatorValue,
  };
};

export default safePasswordConfigurationAdapter;
