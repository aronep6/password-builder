import type { BinaryToTextEncoding } from "../types";

const allowedHashDigests: BinaryToTextEncoding[] = [
  "base64",
  "base64url",
  "hex",
  "binary",
];

export default allowedHashDigests;
