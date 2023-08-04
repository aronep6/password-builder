import { createHmac } from "node:crypto";

interface Hash {
  salt: string;
  hashedPassword: string;
}

type BinaryToTextEncoding = "base64" | "base64url" | "hex" | "binary";
type HashAlgorithm = "sha256" | "sha512";

interface CommonPasswordConfiguration {
  hashAlgorithm?: HashAlgorithm;
  hashDigest?: BinaryToTextEncoding;
}

class PasswordBuilder {
  private static hashAlgorithm: HashAlgorithm = "sha512";
  private static hashDigest: BinaryToTextEncoding = "hex";

  private static hasher = (
    password: string,
    salt: string,
    configuration?: CommonPasswordConfiguration
  ): Pick<Hash, "hashedPassword"> => {
    if (configuration) {
      if (configuration.hashAlgorithm) {
        this.hashAlgorithm = configuration.hashAlgorithm;
      }
      if (configuration.hashDigest) {
        this.hashDigest = configuration.hashDigest;
      }
    }

    const hash = createHmac(this.hashAlgorithm, salt);
    hash.update(password);
    const value = hash.digest(this.hashDigest);

    return {
      hashedPassword: `${salt}.${value}`,
    };
  };

  public static hash = (
    password: string,
    salt: string,
    configuration?: CommonPasswordConfiguration
  ): string => {
    if (password == null || salt == null) {
      throw new Error("Must Provide Password and salt values");
    }
    if (typeof password !== "string" || typeof salt !== "string") {
      throw new Error(
        "password must be a string and salt must either be a salt string or a number of rounds"
      );
    }
    return this.hasher(password, salt, configuration).hashedPassword;
  };

  public static verify = (
    password: string,
    hashedPassword: string,
    configuration?: CommonPasswordConfiguration
  ): boolean => {
    if (hashedPassword == null) {
      throw new Error("Must Provide hashedPassword");
    }

    const subPass = hashedPassword.split(".");

    const passwordHashConfiguration: Hash = {
      salt: subPass[0],
      hashedPassword: subPass[1],
    };

    if (
      typeof password !== "string" ||
      typeof passwordHashConfiguration !== "object"
    ) {
      throw new Error(
        "password must be a String and hash must be an Object of { salt, hashedPassword }"
      );
    }

    const hash = this.hash(
      password,
      passwordHashConfiguration.salt,
      configuration
    );

    if (password == null || hash == null) {
      throw new Error("password and hash is required to compare");
    }

    if (hash === hashedPassword) {
      return true;
    }
    return false;
  };
}

export default PasswordBuilder;
