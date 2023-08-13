import type { SafePasswordConfiguration } from "./interfaces";

const defaultPasswordConfiguration: SafePasswordConfiguration = {
  hashAlgorithm: "sha512",
  hashDigest: "hex",
  inSeparator: ".",
};

export default defaultPasswordConfiguration;
