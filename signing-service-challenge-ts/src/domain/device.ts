import { Algorithm } from "../crypto/signer";
import { DeviceEntry, deviceStorage } from "../persistence/inMemory";

export class Device {
  private id: string;
  private algorithm: Algorithm;
  private label: string | null;
  private signatureCounter: number;
  private lastSignature: string | null;
  private publicKey: string;
  private privateKey: string;

  private constructor(
    id: string,
    algorithm: Algorithm,
    label: string | null,
    signatureCounter: number,
    lastSignature: string | null,
    publicKey: string,
    privateKey: string
  ) {
    this.id = id;
    this.algorithm = algorithm;
    this.label = label;
    this.signatureCounter = signatureCounter;
    this.lastSignature = lastSignature;
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  public getId(): string {
    return this.id;
  }

  public getAlgorithm(): Algorithm {
    return this.algorithm;
  }

  /**
   * Update the label field before save.
   *
   * @param label
   */
  public setLabel(label: string | null) {
    this.label = label;
  }

  public getLabel(): string | null {
    return this.label;
  }

  /**
   * Add 1 to the signatureCounter
   */
  public incrementSignatureCounter() {
    this.signatureCounter++;
  }

  public getSignatureCounter(): number {
    return this.signatureCounter;
  }

  /**
   * Update the lastSignature before save.
   *
   * @param lastSignature
   */
  public setLastSignature(lastSignature: string) {
    this.lastSignature = lastSignature;
  }

  public getLastSignature(): string | null {
    return this.lastSignature;
  }

  public getPublicKey(): string {
    return this.publicKey;
  }

  public getPrivateKey(): string {
    return this.privateKey;
  }

  private static fromDeviceEntry(entry: DeviceEntry): Device {
    return new Device(
      entry.id,
      entry.algorithm,
      entry.label,
      entry.signatureCounter,
      entry.lastSignature,
      entry.publicKey,
      entry.privateKey
    );
  }

  /**
   * Store a new device or throw an error if a device with the same id
   * already exists.
   *
   * @param id
   * @param algorithm
   * @param label
   * @returns the created device
   */
  public static create(
    id: string,
    algorithm: Algorithm,
    label: string | undefined,
    publicKey: string,
    privateKey: string
  ): Device {
    const entry: DeviceEntry = {
      id,
      algorithm,
      label: label || null,
      signatureCounter: 0,
      lastSignature: null,
      publicKey,
      privateKey,
    };

    // store the device as new
    deviceStorage.create(entry);

    return this.fromDeviceEntry(entry);
  }

  /**
   * Find a device by id, if the device doesn't exists return null.
   *
   * @param id
   * @returns the device or null if doesn't exists
   */
  public static findById(id: string): Device | null {
    const entry = deviceStorage.findById(id);
    if (entry === null) {
      return null;
    }

    return this.fromDeviceEntry(entry);
  }

  /**
   * Update this existing device in the storage or throw an error if the device doesn't exists.
   * It should be used after calling a setter.
   *
   * @returns this
   */
  public update(): Device {
    const entry: DeviceEntry = {
      id: this.id,
      algorithm: this.algorithm,
      label: this.label,
      signatureCounter: this.signatureCounter,
      lastSignature: this.lastSignature,
      publicKey: this.publicKey,
      privateKey: this.privateKey,
    };

    deviceStorage.update(entry);

    return this;
  }
}
