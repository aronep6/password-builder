import type {
  Hash,
  CommonPasswordConfiguration,
  SafePasswordConfiguration,
} from "./interfaces";
import { createHmac, randomBytes } from "node:crypto";
import safeCommonPasswordConfigurationAdapter from "./adapter/safe-password-configuration.adapter";

class PasswordBuilder {
  private static defaultSaltRounds = 11;

  public static generateSalt = (
    rounds: number = this.defaultSaltRounds
  ): string => {
    if (typeof rounds !== "number") {
      throw new Error("rounds param must be a number");
    }

    if (rounds < 0) {
      throw new Error("rounds param must be greater than 0");
    }

    if (rounds > 13) {
      console.warn(
        "[PasswordBuilder]: Consider setting rounds param to 13 or lower for production, as this may cause high CPU usage."
      );
    }

    const salt = randomBytes(Math.ceil(rounds / 2)).toString("hex");

    return salt.slice(0, rounds);
  };

  private static hasher = (
    password: string,
    salt: string,
    conf: SafePasswordConfiguration
  ): Pick<Hash, "hashedPassword"> => {
    const hash = createHmac(conf.hashAlgorithm, salt);
    hash.update(password);
    const value = hash.digest(conf.hashDigest);

    return {
      hashedPassword: `${salt}${conf.inSeparator}${value}`,
    };
  };

  public static hash = (
    password: string,
    salt: string,
    configuration?: CommonPasswordConfiguration | SafePasswordConfiguration
  ): string => {
    if (password == null || salt == null) {
      throw new Error("Must Provide Password and salt values");
    }
    if (typeof password !== "string" || typeof salt !== "string") {
      throw new Error(
        "password must be a string and salt must either be a salt string or a number of rounds"
      );
    }

    const conf = safeCommonPasswordConfigurationAdapter(configuration);

    return this.hasher(password, salt, conf).hashedPassword;
  };

  public static verify = (
    password: string,
    hashedPassword: string,
    configuration?: CommonPasswordConfiguration
  ): boolean => {
    if (hashedPassword == null) {
      throw new Error("Must Provide hashedPassword");
    }

    const conf = safeCommonPasswordConfigurationAdapter(configuration);

    const subPass = hashedPassword.split(conf.inSeparator);

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

    const hash = this.hasher(
      password,
      passwordHashConfiguration.salt,
      conf
    ).hashedPassword;

    if (password == null || hash == null) {
      throw new Error("password and hash is required to compare");
    }

    if (hash === hashedPassword && password.length > 0 && hash.length > 0) {
      return true;
    }
    return false;
  };
}

export default PasswordBuilder;
