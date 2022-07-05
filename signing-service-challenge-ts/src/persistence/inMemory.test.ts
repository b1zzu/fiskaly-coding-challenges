import { assert } from "chai";
import { Algorithm } from "../crypto/signer";
import { Device } from "../domain/device";
import { DeviceStorage } from "./inMemory";

/**
 * Create a DeviceStorage for testing with some pre-loaded data.
 */
function deviceStorageSetup(): DeviceStorage {
  const storage = new DeviceStorage();

  storage.create({
    id: "test-rsa",
    algorithm: Algorithm.RSA,
    label: "Test label",
    lastSignature: null,
    privateKey: "private",
    publicKey: "public",
    signatureCounter: 0,
  });

  storage.create({
    id: "test-ec",
    algorithm: Algorithm.EC,
    label: "Test label",
    lastSignature: "old-signature",
    privateKey: "private",
    publicKey: "public",
    signatureCounter: 4,
  });

  return storage;
}

describe("DeviceStorage", () => {
  it("create two devices with the same id should fail", () => {
    const storage = deviceStorageSetup();

    // create a device with same id should fail
    assert.throws(
      () =>
        storage.create({
          id: "test-ec",
          algorithm: Algorithm.EC,
          label: "Some other labels",
          lastSignature: null,
          privateKey: "private",
          publicKey: "public",
          signatureCounter: 0,
        }),
      "a device with the same id already exists"
    );
  });

  it("find by id should return previously created device", () => {
    const storage = deviceStorageSetup();

    const device = storage.findById("test-rsa");
    assert.isNotNull(device);
    assert.equal(device?.id, "test-rsa");
    assert.equal(device?.algorithm, Algorithm.RSA);
    assert.equal(device?.label, "Test label");
  });

  it("update should update an existing device", () => {
    const storage = deviceStorageSetup();

    storage.update({
      id: "test-ec",
      algorithm: Algorithm.EC,
      label: "Test label",
      lastSignature: "another-signature",
      privateKey: "private",
      publicKey: "public",
      signatureCounter: 5,
    });

    const device = storage.findById("test-ec");
    assert.isNotNull(device);
    assert.equal(device?.lastSignature, "another-signature");
    assert.equal(device?.signatureCounter, 5);
  });

  it("update a device that doesn't already exists should fail", () => {
    const storage = deviceStorageSetup();

    assert.throw(
      () =>
        storage.update({
          id: "test-update",
          algorithm: Algorithm.EC,
          label: "Test label",
          lastSignature: "another-signature",
          privateKey: "private",
          publicKey: "public",
          signatureCounter: 5,
        }),
      "the device to update does not exists"
    );
  });
});
