import { sign as signEc } from "./ecdsa";
import { sign as signRsa } from "./rsa";

export interface Signer {
  sign: (dataToBeSigned: string[]) => string[] | Error;
}

export enum Algorithm {
  EC = "EC",
  RSA = "RSA",
}

export default function sign(
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
