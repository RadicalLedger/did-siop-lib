import { Identity } from "../src/core/identity";
import { defaultResolver, specificResolvers } from "./data/identity.testdata";

//Set the default timeout interval to 17000 ms for all tests and before/after hooks
jest.setTimeout(17000);

describe("002. Identity functions", () => {
  test("a. Using default resolver", async () => {
    const did = defaultResolver;
    let identity = new Identity();
    let resolvedDID = await identity.resolve(defaultResolver.didDocument.id);
    expect(resolvedDID).toEqual(defaultResolver.didDocument.id);
    expect(identity.isResolved()).toBeTruthy();
  });

  describe.each(specificResolvers)("($tag)", ({ didDocument, resolver }) => {
    test("b. Using soecific resolver", async () => {
      const did = didDocument.id;
      let identity = new Identity();
      identity.addResolvers([resolver]);

      let resolvedDID = await identity.resolve(did);
      expect(resolvedDID).toEqual(did);
      expect(identity.isResolved()).toBeTruthy();
    });
  });
});
