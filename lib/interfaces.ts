export interface Hash {
  salt: string;
  hashedPassword: string;
}

export type BinaryToTextEncoding = "base64" | "base64url" | "hex" | "binary";
export type HashAlgorithm = "sha256" | "sha512";

export interface CommonPasswordConfiguration {
  hashAlgorithm?: HashAlgorithm;
  hashDigest?: BinaryToTextEncoding;
}
