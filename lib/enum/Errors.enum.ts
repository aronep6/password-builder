export enum PSBErrors {
  NoConfigurationProvided = "[PasswordBuilder]: No configuration provided. Default configuration will be used.",
  ConfigurationMustBeAnObjectOrUndefined = "[PasswordBuilder]: The configuration must be an valid configuration object or undefined.",
  ConfigurationMustContainHashAlgorithmAndHashDigest = "[PasswordBuilder]: Configuration must contain hashAlgorithm and hashDigest.",
  HashAlgorithmAndHashDigestMustBeStrings = "[PasswordBuilder]: hashAlgorithm and hashDigest must be strings.",
}
