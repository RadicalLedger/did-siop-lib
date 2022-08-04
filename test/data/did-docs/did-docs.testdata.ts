import fs from "fs";
import yargs from "yargs";
import path from "path";
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

interface DidDocument {
  "@context": string[];
  id: string;
  verficationMethod: string[];
  authentication: {
    id: string;
    type: string;
    controller: string;
    blockchainAccountId: string;
  }[];
  assertionMethod: string[];
}

interface DidTestData {
  name: string;
  data: {
    didDocument: DidDocument;
    keys: DidKey[];
  };
}

const DEFAULT_TEST_DATA_FILE = "default.json";

function getDidTestData(filename: string): DidTestData {
  const filepath = path.join(__dirname, filename);
  const json = fs.readFileSync(filepath, { encoding: "utf-8" });
  return JSON.parse(json) as DidTestData;
}

const argv = yargs(process.argv).argv;
const files = fs
  .readdirSync(__dirname)
  .filter((file) => path.extname(file).toLowerCase() === ".json");
const didTestDataList: DidTestData[] = [];
const arg = argv;
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
