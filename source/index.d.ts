type BinaryToTextEncoding = "base64" | "base64url" | "hex" | "binary";
type HashAlgorithm = "sha256" | "sha512";
interface CommonPasswordConfiguration {
    hashAlgorithm?: HashAlgorithm;
    hashDigest?: BinaryToTextEncoding;
}
declare class PasswordBuilder {
    private static hashAlgorithm;
    private static hashDigest;
    private static defaultSaltRounds;
    static generateSalt: (rounds?: number) => string;
    private static hasher;
    static hash: (password: string, salt: string, configuration?: CommonPasswordConfiguration) => string;
    static verify: (password: string, hashedPassword: string, configuration?: CommonPasswordConfiguration) => boolean;
}
export default PasswordBuilder;
