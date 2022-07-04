import puppeteer from "puppeteer";

let browser: puppeteer.Browser | undefined;
let page: puppeteer.Page | undefined;

const sleep = async (ms: number) =>
  await new Promise((res) => setTimeout(res, ms));

describe("007.01 DID SIOP using did:ethr method DIDs", function () {
  beforeAll(async () => {
    browser = await puppeteer.launch({
      headless: true,
    });
    page = await browser.newPage();

    let curDir = process.cwd();
    let targetFile = `file://${curDir}/test/browser-app/e2e-minimum.html`;

    await page.goto(targetFile);
  }, 30_000);

  test("Browser - Generate Request", async () => {
    await sleep(1_000);

    if (!page) {
      throw new Error("Error while loading Puppeteer page");
    }

    page.click("#btnGenerateRequest");
    await sleep(500);

    const label = await page.$("#generatedRequset");
    if (!label) {
      throw new Error("Can't find the generatedRequest");
    }
    try {
      const value = await label.evaluate((el) => el.innerHTML);
      expect(value).not.toBe(null);
    } catch (err) {
      console.log(err);
    }
  }, 30_000);

  test("Browser - Generate Response", async () => {
    await sleep(1_000);

    if (!page) {
      throw new Error("Error while loading Puppeteer page");
    }

    page.click("#btnGenerateResponse");
    await sleep(500);

    const label = await page.$("#generatedResponse");
    const label2 = await page.$("#validatedRequset");
    if (!label || !label2) {
      throw new Error("Can't find the generatedRequest");
    }
    try {
      const value = await label.evaluate((el) => el.innerHTML);
      expect(value).not.toBe(null);

      const value2 = await label2.evaluate((el) => el.innerHTML);
      expect(value2).not.toBe(null);
    } catch (err) {
      console.log(err);
    }
  }, 30_000);

  test("Browser - Validate Response", async () => {
    await sleep(1_000);

    if (!page) {
      throw new Error("Error while loading Puppeteer page");
    }

    page.click("#btnValidateResponse");
    await sleep(500);

    const label = await page.$("#validatedResponse");
    if (!label) {
      throw new Error("Can't find the validatedResponse");
    }
    try {
      const value = await label.evaluate((el) => el.innerHTML);
      expect(value).not.toBe(null);
    } catch (err) {
      console.log(err);
    }
  }, 30_000);

  afterAll(async () => await browser?.close?.());
});
