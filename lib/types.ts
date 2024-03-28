export type Hash = {
  salt: string;
  hashedPassword: string;
};

export type BinaryToTextEncoding = "base64" | "base64url" | "hex" | "binary";

export type HashAlgorithm = "sha256" | "sha512";

export type CommonPasswordConfiguration = {
  hashAlgorithm?: HashAlgorithm;
  hashDigest?: BinaryToTextEncoding;
  inSeparator?: string;
};

export type SafePasswordConfiguration = {
  hashAlgorithm: HashAlgorithm;
  hashDigest: BinaryToTextEncoding;
  inSeparator: string;
};
