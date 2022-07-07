import { Identity } from "../src/core/identity";
import { KeyDidResolver } from "../src/core/identity/resolvers";
import { TD_DID_DOCS } from "./data/did-docs.testdata";

describe("002. Identity functions", function () {
  jest.setTimeout(17000);
  test("a. Using default resolver", async () => {
    let identity = new Identity();
    let did1 = TD_DID_DOCS.ethr_rinkeby_1.didDocument.id;

    let resolvedDID = await identity.resolve(did1);
    expect(resolvedDID).toEqual(did1);
    expect(identity.isResolved()).toBeTruthy();
  });
  test("b. Using soecific resolver (did:key)", async () => {
    let keyResolver = new KeyDidResolver("key");
    let did2 = TD_DID_DOCS.key_2018_2.didDocument.id;

    let identity = new Identity();
    identity.addResolvers([keyResolver]);

    let resolvedDID = await identity.resolve(did2);
    expect(resolvedDID).toEqual(did2);
    expect(identity.isResolved()).toBeTruthy();
  });
});
