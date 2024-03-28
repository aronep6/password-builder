import type { SafePasswordConfiguration } from "./types";

const defaultPasswordConfiguration: SafePasswordConfiguration = {
  hashAlgorithm: "sha512",
  hashDigest: "hex",
  inSeparator: ".",
};

export default defaultPasswordConfiguration;
