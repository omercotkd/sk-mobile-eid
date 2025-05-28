import { HashType } from './hashType';

/**
 * This Enum is inspired by the java implementation of the MID client
 * https://github.com/SK-EID/mid-rest-java-client/blob/cf04a090e7cd932633db5bd25b6ce174ab136042/src/main/java/ee/sk/mid/MidHashType.java
 *
 * due to enum limitations in TypeScript (only string or numeric values are allowed),
 * we use a namespace with functions and a constant object
 * to represent the enum values and have similar functionality,
 * and also limit the hashes to the ones used in the MID client.
 */
export enum MidHashTypes {
  SHA256 = 'SHA256',
  SHA384 = 'SHA384',
  SHA512 = 'SHA512',
}

// Include here all the hash types used in the MID client.
const MidHashTypesEnumValues = {
  SHA256: new HashType(
    MidHashTypes.SHA256,
    256,
    new Uint8Array([
      0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
      0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
    ]),
    'sha256',
  ),
  SHA384: new HashType(
    MidHashTypes.SHA384,
    384,
    new Uint8Array([
      0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
      0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
    ]),
    'sha384',
  ),
  SHA512: new HashType(
    MidHashTypes.SHA512,
    512,
    new Uint8Array([
      0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
      0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
    ]),
    'sha512',
  ),
};

export namespace MidHashTypes {
  export function getValue(hashType: MidHashTypes): HashType {
    switch (hashType) {
      case MidHashTypes.SHA256:
        return MidHashTypesEnumValues.SHA256;
      case MidHashTypes.SHA384:
        return MidHashTypesEnumValues.SHA384;
      case MidHashTypes.SHA512:
        return MidHashTypesEnumValues.SHA512;
      default:
        throw new Error(`Unknown hash type: ${hashType}`);
    }
  }

  export function fromHashTypeName(hashTypeName: string): MidHashTypes {
    for (const key of Object.keys(MidHashTypesEnumValues) as Array<
      keyof typeof MidHashTypesEnumValues
    >) {
      if (MidHashTypesEnumValues[key].hashTypeName === hashTypeName) {
        return MidHashTypes[key];
      }
    }
    throw new Error(`Unknown hash type name: ${hashTypeName}`);
  }

  export function fromBytesLength(lengthInBytes: number): MidHashTypes {
    for (const key of Object.keys(MidHashTypesEnumValues) as Array<
      keyof typeof MidHashTypesEnumValues
    >) {
      if (MidHashTypesEnumValues[key].getLengthInBytes() === lengthInBytes) {
        return MidHashTypes[key];
      }
    }
    throw new Error(`Unknown hash length: ${lengthInBytes}`);
  }

  export function getLengthInBytes(hashType: MidHashTypes): number {
    return getValue(hashType).getLengthInBytes();
  }
  export function getDigestInfoPrefix(hashType: MidHashTypes): Uint8Array {
    return getValue(hashType).getDigestInfoPrefix();
  }
  export function getAlgorithm(hashType: MidHashTypes): any {
    return getValue(hashType).algorithm;
  }
  export function getHashTypeName(hashType: MidHashTypes): string {
    return getValue(hashType).hashTypeName;
  }
}
