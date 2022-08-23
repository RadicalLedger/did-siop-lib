import { Identity } from "../src/core/identity";
import { IDENTITY_TD } from "./data/identity.testdata";

//Set the default timeout interval to 17000 ms for all tests and before/after hooks
jest.setTimeout(17000);

describe("002. Identity functions", () => {
  test("a. Using default resolver", async () => {
    const didId = IDENTITY_TD.defaultResolver.didDocument.id;
    const identity = new Identity();
    const resolvedDID = await identity.resolve(didId);
    expect(resolvedDID).toEqual(didId);
    expect(identity.isResolved()).toBeTruthy();
  });

  describe.each(IDENTITY_TD.specificResolvers)(
    "($tag)",
    ({ didDocument, resolver }) => {
      test("b. Using soecific resolver", async () => {
        const did = didDocument.id;
        let identity = new Identity();
        identity.addResolvers([resolver]);

        let resolvedDID = await identity.resolve(did);
        expect(resolvedDID).toEqual(did);
        expect(identity.isResolved()).toBeTruthy();
      });
    }
  );
});
