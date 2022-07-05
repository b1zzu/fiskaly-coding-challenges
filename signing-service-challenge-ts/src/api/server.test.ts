import chai, { assert } from "chai";
import chaiHttp from "chai-http";
import { sign } from "crypto";
import { verify } from "../crypto/signer";
import { Algorithm } from "../crypto/signer";
import server from "./server";

chai.use(chaiHttp);

function base64(s: string): string {
  return Buffer.from(s, "utf-8").toString("base64");
}

describe("Device", () => {
  it("create a device should generate a key pair", async () => {
    const response = await chai
      .request(server)
      .post("/device")
      .send({ id: "test", algorithm: "RSA" });

    assert.equal(response.status, 200);
    assert.isNotEmpty(response.text);

    const device = JSON.parse(response.text);

    assert.equal(device["id"], "test");
    assert.isNotEmpty(device["public_key"]);
  });

  it("create a device with the an incorrect id should fail", async () => {
    const response = await chai
      .request(server)
      .post("/device")
      .send({ id: "test/ incorrect", algorithm: "RSA" });

    assert.equal(response.status, 400);
    assert.isNotEmpty(response.text);
    assert.equal(
      JSON.parse(response.text)["error"],
      "the id can only contain alphanumeric characters separated by dashes, it must start with the alphabetic character, end with an alphanumeric characters and can only have one consecutive dash"
    );
  });

  it("create a device without id should fail", async () => {
    const response = await chai
      .request(server)
      .post("/device")
      .send({ algorithm: "RSA" });

    assert.equal(response.status, 400);
    assert.isNotEmpty(response.text);
    assert.equal(JSON.parse(response.text)["error"], "id is undefined");
  });

  it("create a device without algorithm should fail", async () => {
    const response = await chai
      .request(server)
      .post("/device")
      .send({ id: "test-without-algorithm" });

    assert.equal(response.status, 400);
    assert.isNotEmpty(response.text);
    assert.equal(JSON.parse(response.text)["error"], "algorithm is undefined");
  });

  it("create a device with a wrong algorithm should fail", async () => {
    const response = await chai
      .request(server)
      .post("/device")
      .send({ id: "test-with-wrong-algorithm", algorithm: "SHA" });

    assert.equal(response.status, 400);
    assert.isNotEmpty(response.text);
    assert.equal(
      JSON.parse(response.text)["error"],
      "algorithm is not EC or RSA"
    );
  });

  it("create and verify RSA signature", async () => {
    const id = "test-rsa";
    const data = "My data to be signed using the RSA algorithm!";

    // create a device
    let response = await chai
      .request(server)
      .post("/device")
      .send({ id: id, algorithm: "RSA" });

    assert.equal(response.status, 200);
    const publicKey = JSON.parse(response.text)["public_key"];
    assert.isNotEmpty(publicKey);

    // sign a piece of data
    response = await chai
      .request(server)
      .post(`/device/${id}/sign`)
      .send({ data: data });

    assert.equal(response.status, 200);
    assert.isNotEmpty(response.text);

    const signBody = JSON.parse(response.text);
    const signature = signBody["signature"];
    const signedData = signBody["signed_data"];
    assert.isNotNull(signature);
    assert.equal(signedData, `0_${base64(data)}_${base64(id)}`);

    // verify the signature
    assert.isTrue(verify(Algorithm.RSA, signedData, signature, publicKey));
  });

  it("create and verify EC signature", async () => {
    const id = "test-ec";
    const data = "My data to be signed using the EC algorithm!";

    // create a device
    let response = await chai
      .request(server)
      .post("/device")
      .send({ id: id, algorithm: "EC" });

    assert.equal(response.status, 200);
    const publicKey = JSON.parse(response.text)["public_key"];
    assert.isNotEmpty(publicKey);

    // sign a piece of data
    response = await chai
      .request(server)
      .post(`/device/${id}/sign`)
      .send({ data: data });

    assert.equal(response.status, 200);
    assert.isNotEmpty(response.text);

    const signBody = JSON.parse(response.text);
    const signature = signBody["signature"];
    const signedData = signBody["signed_data"];
    assert.isNotNull(signature);
    assert.equal(signedData, `0_${base64(data)}_${base64(id)}`);

    // verify the signature
    assert.isTrue(verify(Algorithm.EC, signedData, signature, publicKey));
  });

  it("create multiple signature with the same device should should increase the counter and use the previous signature as part of the new signed data", async () => {
    const id = "test-multi-sign";
    const firstData = "My data to be signed using the EC algorithm!";
    const secondData = "My new data to be signed!";

    // create a device
    let response = await chai
      .request(server)
      .post("/device")
      .send({ id: id, algorithm: "EC" });
    assert.equal(response.status, 200);

    // sign a piece of data
    response = await chai
      .request(server)
      .post(`/device/${id}/sign`)
      .send({ data: firstData });

    assert.equal(response.status, 200);
    assert.isNotEmpty(response.text);

    let signBody = JSON.parse(response.text);
    const firstSignature = signBody["signature"];
    const firstSignedData = signBody["signed_data"];
    assert.isNotNull(firstSignature);
    // the first time the signature_counter is 0 and because there is not a previous signature
    // the device id in base64 encode is used
    assert.equal(firstSignedData, `0_${base64(firstData)}_${base64(id)}`);

    // sign data a second time
    response = await chai
      .request(server)
      .post(`/device/${id}/sign`)
      .send({ data: secondData });

    assert.equal(response.status, 200);
    assert.isNotEmpty(response.text);

    signBody = JSON.parse(response.text);
    const secondSignature = signBody["signature"];
    const secondSignedData = signBody["signed_data"];
    assert.isNotNull(secondSignature);
    // for each signature after the the first one the signature_counter is increased by one and the 
    // previous signature is added to the signed data
    assert.equal(secondSignedData, `1_${base64(secondData)}_${firstSignature}`);
  });
});
