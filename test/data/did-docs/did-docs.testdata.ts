const fs = require("fs");
const path = require("path");
import { DidDocument } from "../../../src";
import { DidVerificationKey } from "../../../src/core/identity";

interface DidTestData {
  name: string;
  data: {
    user: {
      didDocument: DidDocument;
      keys: DidVerificationKey[];
      resolvers: {
        type: any;
        methodName: string;
        crypto_suite?: string;
      }[];
    };
    rp: {
      didDocument: DidDocument;
      keys: DidVerificationKey[];
      resolvers: {
        type: any;
        methodName: string;
        crypto_suite?: string;
      }[];
    };
  };
}

console.log(process.argv);

class DidTestData {
  private static DEFAULT_TEST_DATA_FILE = "default.json";
  private static didTestDataList: DidTestData[] = [];

  public static get testData(): DidTestData[] {
    if (this.didTestDataList.length === 0) {
      this.loadDidTestData();
    }
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
    return fs
      .readdirSync(dirname)
      .filter((file: string) => path.extname(file).toLowerCase() === ".json");
  }

  private static loadDidTestData() {
    //See jest.config.js
    const arg = process.env?.TARGET_DID_TEST_DATA;

    const files = this.readDir(__dirname);
    if (arg) {
      files
        .map((filename: string) => this.readDidTestData(filename))
        .filter(
          (testData: DidTestData) => arg === testData.name || arg === "all"
        )
        .forEach((testData: DidTestData) => {
          this.didTestDataList.push(testData);
        });
    } else {
      this.didTestDataList.push(
        this.readDidTestData(this.DEFAULT_TEST_DATA_FILE)
      );
    }
  }
}
const a = DidTestData.testData;
export default a;
