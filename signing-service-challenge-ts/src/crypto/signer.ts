export interface Signer {
  sign: (dataToBeSigned: string[]) => string[] | Error;
}

export enum Algorithm {
  ECC = "ECC",
  RSA = "RSA",
}
