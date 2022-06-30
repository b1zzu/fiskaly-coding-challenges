import bodyParser from "body-parser";
import express, { Response } from "express";
import generateKeyPair from "../crypto/generation";
import { Algorithm } from "../crypto/signer";
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
  if (id.length < 4 || id.length > 16) {
    return error(res, 400, "the id must be min 4 characters and max 16");
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
    return error(res, 400, "algorithm is not ECC or RSA");
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

    if (label.length > 64) {
      return error(res, 400, "the label must be max 64 characters");
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
      publicKey: device.getPublicKey(),
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
