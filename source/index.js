"use strict";
var _a;
Object.defineProperty(exports, "__esModule", { value: true });
const node_crypto_1 = require("node:crypto");
class PasswordBuilder {
}
_a = PasswordBuilder;
PasswordBuilder.hashAlgorithm = "sha512";
PasswordBuilder.hashDigest = "hex";
PasswordBuilder.defaultSaltRounds = 11;
PasswordBuilder.generateSalt = (rounds = _a.defaultSaltRounds) => {
    if (typeof rounds !== "number") {
        throw new Error("rounds param must be a number");
    }
    if (rounds < 0) {
        throw new Error("rounds param must be greater than 0");
    }
    if (rounds > 13) {
        console.warn("[PasswordBuilder]: Consider setting rounds param to 13 or lower for production, as this may cause high CPU usage.");
    }
    const salt = (0, node_crypto_1.randomBytes)(Math.ceil(rounds / 2)).toString("hex");
    return salt.slice(0, rounds);
};
PasswordBuilder.hasher = (password, salt, configuration) => {
    if (configuration) {
        if (configuration.hashAlgorithm) {
            _a.hashAlgorithm = configuration.hashAlgorithm;
        }
        if (configuration.hashDigest) {
            _a.hashDigest = configuration.hashDigest;
        }
    }
    const hash = (0, node_crypto_1.createHmac)(_a.hashAlgorithm, salt);
    hash.update(password);
    const value = hash.digest(_a.hashDigest);
    return {
        hashedPassword: `${salt}.${value}`,
    };
};
PasswordBuilder.hash = (password, salt, configuration) => {
    if (password == null || salt == null) {
        throw new Error("Must Provide Password and salt values");
    }
    if (typeof password !== "string" || typeof salt !== "string") {
        throw new Error("password must be a string and salt must either be a salt string or a number of rounds");
    }
    return _a.hasher(password, salt, configuration).hashedPassword;
};
PasswordBuilder.verify = (password, hashedPassword, configuration) => {
    if (hashedPassword == null) {
        throw new Error("Must Provide hashedPassword");
    }
    const subPass = hashedPassword.split(".");
    const passwordHashConfiguration = {
        salt: subPass[0],
        hashedPassword: subPass[1],
    };
    if (typeof password !== "string" ||
        typeof passwordHashConfiguration !== "object") {
        throw new Error("password must be a String and hash must be an Object of { salt, hashedPassword }");
    }
    const hash = _a.hash(password, passwordHashConfiguration.salt, configuration);
    if (password == null || hash == null) {
        throw new Error("password and hash is required to compare");
    }
    if (hash === hashedPassword) {
        return true;
    }
    return false;
};
exports.default = PasswordBuilder;
