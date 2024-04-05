import { randomBytes } from "node:crypto";

/**
 * This is the default number of rounds used to generate a salt (by default 11).
 */
const DEFAULT_SALT_ROUNDS: number = 11;

/**
 * This function is used to generate a salt for hashing a password, the salt is used to add complexity to the password hash.
 * @param rounds
 * @returns string
 */
export default function generateSalt(
  rounds: number = DEFAULT_SALT_ROUNDS
): string {
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
}
