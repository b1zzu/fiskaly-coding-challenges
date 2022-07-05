import { Algorithm } from "../crypto/signer";

export interface DeviceEntry {
  id: string;
  algorithm: Algorithm;
  label: string | null;
  signatureCounter: number;
  lastSignature: string | null;
  publicKey: string;
  privateKey: string;
}

export class DeviceStorage {
  /**
   * The created devices array
   */
  private devices: DeviceEntry[] = [];

  /**
   * The index of the device in the devices array
   */
  private devicesIndexById: { [id: string]: number } = {};

  public create(device: DeviceEntry) {
    if (this.devicesIndexById[device.id] !== undefined) {
      throw new Error("a device with the same id already exists");
    }

    // add the new device to the list and store the index
    // in the devicesIndexById map
    const length = this.devices.push(device);

    const index = length - 1;

    this.devicesIndexById[device.id] = index;
  }

  public findById(id: string): DeviceEntry | null {
    const index = this.devicesIndexById[id];
    if (index === undefined) {
      return null;
    }

    return this.devices[index];
  }

  public update(device: DeviceEntry) {
    const index = this.devicesIndexById[device.id];
    if (index === undefined) {
      throw new Error("the device to update does not exists");
    }

    // overwrite the device with the same id in the
    // same position
    this.devices[index] = device;
  }
}

export const deviceStorage = new DeviceStorage();
