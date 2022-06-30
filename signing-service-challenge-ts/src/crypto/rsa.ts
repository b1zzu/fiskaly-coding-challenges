import { KeyPair } from "./generation";
import crypto from "crypto";

export function sign(dataToBeSigned: string, privateKey: string): string {
  try {
    const cipher = crypto.createCipheriv(
      "aes-192-cbc",
      crypto.scryptSync(privateKey, "fiskaly is AWESOME!", 24),
      crypto.randomBytes(16)
    );
    let encrypted = cipher.update(dataToBeSigned);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return encrypted.toString("base64");
  } catch (e) {
    console.error(e);
    throw e;
  }
}
