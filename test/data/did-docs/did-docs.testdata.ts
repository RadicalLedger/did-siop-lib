const fs = require("fs");
const path = require("path");
import yargs from "yargs";
import { ALGORITHMS, KEY_FORMATS, KTYS } from "../../../src/core/globals";

interface DidKey {
  id: string;
  kty: KTYS;
  alg: ALGORITHMS[];
  format: KEY_FORMATS;
  publicKey: string;
  privateKey: string;
  address: string;
  identifier: string;
}

interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  blockchainAccountId: string;
}

interface DidDocument {
  "@context": string[];
  id: string;
  verificationMethod: VerificationMethod[];
  assertionMethod: string[];
  authentication: string[];
  capabilityDelegation: string[];
  capabilityInvocation: string[];
  keyAgreement: [
    {
      id: string;
      type: string;
      controller: string;
      publicKeyBase58: string;
    }
  ];
}

interface DidTestData {
  name: string;
  data: {
    user: {
      didDocument: DidDocument;
      keys: DidKey[];
    };
    rp: {
      didDocument: DidDocument;
      keys: DidKey[];
    };
    keyResolver: {
      methodName: string;
      crypto_suite?: string;
    };
  };
}

console.log(process.argv)

class DidTestData {

  private static DEFAULT_TEST_DATA_FILE = "default.json";
  private static didTestDataList: DidTestData[] = [];

  public static get testData(): DidTestData[] {
    if (this.didTestDataList.length === 0) {
      this.loadDidTestData();
      console.log("loading")
    }
    console.log("Sdfsf")
    return this.didTestDataList;
  }

  private static readDidTestData(filename: string): DidTestData {
    const filepath = path.join(__dirname, filename);
    const json = fs.readFileSync(filepath, { encoding: "utf-8" });
    const testData = JSON.parse(json) as DidTestData;
    this.validateDidTestData(testData);
    return testData;
  }

  private static validateDidTestData(testData: any): void {
    testData === null;
  }

  private static readDir(dirname: string): string[] {
    return fs.readdirSync(dirname)
      .filter((file: string) => path.extname(file).toLowerCase() === ".json");
  }


  private static loadDidTestData() {

    //See jest.config.js
    const arg = process.env?.TARGET_DID_TEST_DATA;

    const files = this.readDir(__dirname)
    if (arg) {
      files
        .map((filename: string) => this.readDidTestData(filename))
        .filter((testData: DidTestData) => arg === testData.name || arg === "all")
        .forEach((testData: DidTestData) => {
          this.didTestDataList.push(testData);
        });
    } else {
      this.didTestDataList.push(this.readDidTestData(this.DEFAULT_TEST_DATA_FILE));
    }
  }

}
const a = DidTestData.testData
export default a;
