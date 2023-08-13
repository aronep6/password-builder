import type { BinaryToTextEncoding } from "../interfaces";

const allowedHashDigests: BinaryToTextEncoding[] = [
  "base64",
  "base64url",
  "hex",
  "binary",
];

export default allowedHashDigests;
