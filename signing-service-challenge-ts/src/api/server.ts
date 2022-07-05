import bodyParser from "body-parser";
import express, { Response } from "express";
import { generateKeyPair } from "../crypto/generation";
import { Algorithm, sign, verify } from "../crypto/signer";
import { Device } from "../domain/device";

const server = express();

server.use(bodyParser.json());

server.get("/health", (req, res) => {
  res.status(200);
  res.send(
    JSON.stringify({
      status: "pass",
      version: "v1",
    })
  );
});

/**
 * Create Device
 */
server.post("/device", async (req, res) => {
  const id: any = req.body.id;
  const algorithm: any = req.body.algorithm;
  let label: any = req.body.label;

  // Validate the id
  if (id === undefined) {
    return error(res, 400, "id is undefined");
  }
  if (!isString(id)) {
    return error(res, 400, "id is not a string");
  }
  if (id.length < 4 || id.length > 64) {
    return error(res, 400, "the id must be min 4 characters and max 64");
  }
  if (!id.match(/^^[a-zA-z]-?([a-zA-z0-9]+-?)*[a-zA-z0-9]$/)) {
    return error(
      res,
      400,
      "the id can only contain alphanumeric characters separated by dashes," +
        " it must start with the alphabetic character, end with an alphanumeric characters" +
        " and can only have one consecutive dash"
    );
  }

  // Validate the algorithm
  if (algorithm === undefined) {
    return error(res, 400, "algorithm is undefined");
  }
  if (!isString(algorithm)) {
    return error(res, 400, "algorithm is not a string");
  }
  if (!isAlgorithm(algorithm)) {
    return error(res, 400, "algorithm is not EC or RSA");
  }

  // Validate the label
  if (label !== undefined) {
    if (!isString(label)) {
      return error(res, 400, "label is not a string");
    }

    if (label.length === 0) {
      // uniform empty label to undefined
      label = undefined;
    }

    if (label.length > 256) {
      return error(res, 400, "the label must be max 256 characters");
    }
  }

  // Check that a device with the same ID doesn't already exists
  if (Device.findById(id) !== null) {
    return error(res, 400, "a device with the same id already exists");
  }

  // Generate the Public/Private keys
  const key = await generateKeyPair(algorithm);

  // Store the new device
  const device = Device.create(id, algorithm, label, key.public, key.private);

  res.status(200);
  res.send(
    JSON.stringify({
      id: device.getId(),
      algorithm: device.getAlgorithm(),
      label: device.getLabel(),
      public_key: device.getPublicKey(),
    })
  );
});

server.post("/device/:id/sign", async (req, res) => {
  const id: string = req.params.id;
  const data: any = req.body.data;

  // Validate the id
  if (id === undefined) {
    return error(res, 400, "id is undefined");
  }

  // Validate the data to sign
  if (data === undefined) {
    return error(res, 400, "data is undefined");
  }
  if (!isString(data)) {
    return error(res, 400, "data is not a string");
  }
  if (data.length === 0) {
    return error(res, 400, "data is empty");
  }

  // Retrieve the device by id
  const device = Device.findById(id);
  if (device === null) {
    return error(res, 400, `the deice with the id: '${id}' does not exists`);
  }

  // Prepare the data to be signed
  const encodedData = Buffer.from(data, "utf-8").toString("base64");
  const signatureCounter = device.getSignatureCounter();
  const lastSignature =
    device.getLastSignature() ||
    Buffer.from(device.getId(), "utf-8").toString("base64");

  const dataToBeSign = `${signatureCounter}_${encodedData}_${lastSignature}`;

  // Sign the data
  const signature = sign(
    device.getAlgorithm(),
    dataToBeSign,
    device.getPrivateKey()
  );

  // Update the device counter and last signature
  device.incrementSignatureCounter();
  device.setLastSignature(signature);
  device.update();

  res.status(200);
  res.send(
    JSON.stringify({
      signature: signature,
      signed_data: dataToBeSign,
    })
  );
});

server.post("/device/:id/verify", async (req, res) => {
  const id: string = req.params.id;
  const signature: any = req.body.signature;
  const signedData: any = req.body.signed_data;

  // Validate the id
  if (id === undefined) {
    return error(res, 400, "id is undefined");
  }

  // Validate signature
  if (signature === undefined) {
    return error(res, 400, "signature is undefined");
  }
  if (!isString(signature)) {
    return error(res, 400, "signature is not a string");
  }
  if (signature.length === 0) {
    return error(res, 400, "signature is empty");
  }

  // Validate signed_data
  if (signedData === undefined) {
    return error(res, 400, "signed_data is undefined");
  }
  if (!isString(signedData)) {
    return error(res, 400, "signed_data is not a string");
  }
  if (signedData.length === 0) {
    return error(res, 400, "signed_data is empty");
  }

  // Retrieve the device by id
  const device = Device.findById(id);
  if (device === null) {
    return error(res, 400, `the deice with the id: '${id}' does not exists`);
  }

  // Verify the signature
  const isValid = verify(device.getAlgorithm(), signedData, signature, device.getPublicKey());

  res.status(200);
  res.send(
    JSON.stringify({
      is_valid: isValid,
    })
  );
});

function error(res: Response, code: number, error: string) {
  res.status(code);
  res.send(JSON.stringify({ error }));
}

function isString(s: any): s is string {
  return typeof s === "string";
}

function isAlgorithm(a: string): a is Algorithm {
  return a in Algorithm;
}

export default server;
