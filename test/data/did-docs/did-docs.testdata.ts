import fs = require("fs");
import path = require("path");
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

const DEFAULT_TEST_DATA_FILE = "default.json";

function getDidTestData(filename: string): DidTestData {
  const filepath = path.join(__dirname, filename);
  const json = fs.readFileSync(filepath, { encoding: "utf-8" });
  const testData = JSON.parse(json) as DidTestData;
  validateDidTestData(testData);
  return testData;
}

function validateDidTestData(testData: any): void {
  console.log(testData);
}

const argv = yargs(process.argv).argv;
const files = fs
  .readdirSync(__dirname)
  .filter((file) => path.extname(file).toLowerCase() === ".json");
const didTestDataList: DidTestData[] = [];
const arg = argv["target"];
if (arg) {
  files
    .map((filename) => {
      return getDidTestData(filename);
    })
    .filter((testData) => arg === testData.name || arg === "all")
    .forEach((testData) => {
      didTestDataList.push(testData);
    });
} else {
  const defaultTestData = getDidTestData(DEFAULT_TEST_DATA_FILE);
  didTestDataList.push(defaultTestData);
}

export default didTestDataList;
