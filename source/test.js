"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const node_assert_1 = __importDefault(require("node:assert"));
const _1 = __importDefault(require("."));
(0, node_test_1.default)("PasswordBuilder.hash()", (t) => __awaiter(void 0, void 0, void 0, function* () {
    yield t.test("PasswordBuilder.hash() should return a string hashed password", (t) => __awaiter(void 0, void 0, void 0, function* () {
        const password = "password_123";
        const salt = "spidermanvsbatman";
        const expectedHash = "spidermanvsbatman.RWbTOAtwP9e55sp0U+3/U7auSjjGAHqK7q0uk77Swbk=";
        const hashedPassword = _1.default.hash(password, salt, {
            hashAlgorithm: "sha256",
            hashDigest: "base64",
        });
        node_assert_1.default.strictEqual(hashedPassword, expectedHash);
    }));
    yield t.test("PasswordBuilder.hash() should return a string hashed password (complex password with special characters and default configuration)", (t) => __awaiter(void 0, void 0, void 0, function* () {
        const password = "hh_2jHSBrs<vXPZX3]MA%jk{bY7[q^$^!d";
        const salt = "B5huQROTsAubI0Foe3";
        const expectedHash = "B5huQROTsAubI0Foe3.C63xQ1CIqI7k5J80I2FW8yd+22erTSBZ0CFHvFWGHug=";
        const hashedPassword = _1.default.hash(password, salt);
        node_assert_1.default.strictEqual(hashedPassword, expectedHash);
    }));
    yield t.test("PasswordBuilder.hash() should throw an error if password is null", (t) => __awaiter(void 0, void 0, void 0, function* () {
        try {
            const password = null;
            const salt = null;
            _1.default.hash(password, salt);
        }
        catch (error) {
            node_assert_1.default.strictEqual(error.message, "Must Provide Password and salt values");
        }
    }));
    yield t.test("PasswordBuilder.hash() should throw an error if password is not a string", (t) => __awaiter(void 0, void 0, void 0, function* () {
        try {
            const password = 123;
            const salt = "hello";
            _1.default.hash(password, salt);
        }
        catch (error) {
            node_assert_1.default.strictEqual(error.message, "password must be a string and salt must either be a salt string or a number of rounds");
        }
    }));
    yield t.test("PasswordBuilder.hash() should throw an error if salt is not a string", (t) => __awaiter(void 0, void 0, void 0, function* () {
        try {
            const password = "hello";
            const salt = 123;
            _1.default.hash(password, salt);
        }
        catch (error) {
            node_assert_1.default.strictEqual(error.message, "password must be a string and salt must either be a salt string or a number of rounds");
        }
    }));
}));
(0, node_test_1.default)("PasswordBuilder.verify()", (t) => __awaiter(void 0, void 0, void 0, function* () {
    yield t.test("PasswordBuilder.verify() should return true if password is valid", (t) => __awaiter(void 0, void 0, void 0, function* () {
        const password = "password_456";
        const expectedHash = "gothamcity.74feb8fa77b7651d3aca2abc075c60d55d5d7f8b053d1b06dc5fc725cf4651acf7ce8adcf2fb392deb4554c967af15e54294892926aed5fed6a2ab5bec66419d";
        const isPasswordValid = _1.default.verify(password, expectedHash, {
            hashAlgorithm: "sha512",
            hashDigest: "hex",
        });
        node_assert_1.default.strictEqual(isPasswordValid, true);
    }));
    yield t.test("PasswordBuilder.verify() should return false if password is invalid", (t) => __awaiter(void 0, void 0, void 0, function* () {
        const password = "password_456";
        const expectedHash = "invalid_hash_value";
        const isPasswordValid = _1.default.verify(password, expectedHash, {
            hashAlgorithm: "sha512",
            hashDigest: "hex",
        });
        node_assert_1.default.strictEqual(isPasswordValid, false);
    }));
    yield t.test("PasswordBuilder.verify() should throw an error if password is null", (t) => __awaiter(void 0, void 0, void 0, function* () {
        try {
            const password = "password";
            const hashedPassword = null;
            _1.default.verify(password, hashedPassword);
        }
        catch (error) {
            node_assert_1.default.strictEqual(error.message, "Must Provide hashedPassword");
        }
    }));
    yield t.test("PasswordBuilder.verify() should throw an error if password is not a string and hash configuration is an object", (t) => __awaiter(void 0, void 0, void 0, function* () {
        try {
            const password = 123;
            const hashedPassword = "hashedPassword";
            const hashConfig = "hashConfig";
            _1.default.verify(password, hashedPassword, hashConfig);
        }
        catch (error) {
            console.log("error", error);
            node_assert_1.default.strictEqual(error.message, "password must be a String and hash must be an Object of { salt, hashedPassword }");
        }
    }));
}));
