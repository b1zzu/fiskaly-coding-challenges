import crypto from "crypto";

export interface Signer {
  sign: (dataToBeSigned: string[]) => string[] | Error;
}

export enum Algorithm {
  EC = "EC",
  RSA = "RSA",
}

/**
 * Sign the passed data using the passed private key
 *
 * @param dataToBeSigned The data to be signed
 * @param privateKey The private key to sign the data, it must be a der pkcs8 key encoded in base64
 * @returns The base64 encoded signature
 */
function signRsa(dataToBeSigned: string, privateKey: string): string {
  return crypto
    .createSign("SHA256")
    .update(dataToBeSigned)
    .end()
    .sign({
      key: Buffer.from(privateKey, "base64"),
      format: "der",
      type: "pkcs8",
      passphrase: "fiskaly is AWESOME",
    })
    .toString("base64");
}

/**
 * Sign the passed data using the passed private key
 *
 * @param dataToBeSigned The data to be signed
 * @param privateKey The private key to sign the data, it must be a der pkcs8 key encoded in base64
 * @returns The base64 encoded signature
 */
function signEc(dataToBeSigned: string, privateKey: string): string {
  return crypto
    .createSign("SHA256")
    .update(dataToBeSigned)
    .end()
    .sign({
      key: Buffer.from(privateKey, "base64"),
      format: "der",
      type: "pkcs8",
    })
    .toString("base64");
}

/**
 * Sign the passed data using the passed private key.
 *
 * @param algorithm The algorithm used to generate the private/public key pair
 * @param dataToBeSigned The data to be signed
 * @param privateKey The private key to sign the data, it must be a der pkcs8 key encoded in base64
 * @returns The base64 encoded signature
 */
export function sign(
  algorithm: Algorithm,
  dataToBeSigned: string,
  privateKey: string
): string {
  switch (algorithm) {
    case Algorithm.EC:
      return signEc(dataToBeSigned, privateKey);
    case Algorithm.RSA:
      return signRsa(dataToBeSigned, privateKey);
  }
}

function verifyRsa(
  dataToVerify: string,
  signature: string,
  publicKey: string
): boolean {
  return crypto
    .createVerify("SHA256")
    .update(dataToVerify)
    .end()
    .verify(
      {
        key: Buffer.from(publicKey, "base64"),
        format: "der",
        type: "pkcs1",
      },
      Buffer.from(signature, "base64")
    );
}

function verifyEc(
  dataToVerify: string,
  signature: string,
  publicKey: string
): boolean {
  return crypto
    .createVerify("SHA256")
    .update(dataToVerify)
    .end()
    .verify(
      {
        key: Buffer.from(publicKey, "base64"),
        format: "der",
        type: "spki",
      },
      Buffer.from(signature, "base64")
    );
}

/**
 * Verify a signature and data previously signed with the private key.
 *
 * @param algorithm The algorithm used to generate the private/public key pair
 * @param dataToVerify The data to be verified
 * @param signature The signature used to sign the data, it must be encoded in base64
 * @param publicKey The private key that will be used to verify the signature, it must be a der pkcs8 key encoded in base64
 * @returns true if the signature is valid otherwise false
 */
export function verify(
  algorithm: Algorithm,
  dataToVerify: string,
  signature: string,
  publicKey: string
): boolean {
  switch (algorithm) {
    case Algorithm.EC:
      return verifyEc(dataToVerify, signature, publicKey);
    case Algorithm.RSA:
      return verifyRsa(dataToVerify, signature, publicKey);
  }
}
