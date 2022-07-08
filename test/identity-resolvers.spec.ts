import {
  CombinedDidResolver,
  EthrDidResolver,
  KeyDidResolver,
} from "../src/core/identity/resolvers";
import { TD_DID_DOCS } from "./data/did-docs.testdata";

describe("001.01 CombinedDidResolver Functionalities with default resolver", function () {
  jest.setTimeout(17000);
  test("a. ability to resolve using default resolver", async () => {
    let did = TD_DID_DOCS.ethr_rinkeby_1.didDocument.id;
    let combinedDidResolver = new CombinedDidResolver("all");
    let resolvedDID = await combinedDidResolver.resolveDidDocumet(did);

    expect(resolvedDID.id).toEqual(did);
  });
});

describe("001.02 CombinedDidResolver Functionalities with given Resolver ", function () {
  jest.setTimeout(17000);
  test("a. ability to add EthrDidResolver and resolve a DID", async () => {
    let did = TD_DID_DOCS.ethr_rinkeby_1.didDocument.id;
    let combinedDidResolver = new CombinedDidResolver("");
    let ethrResolver = new EthrDidResolver("ethr");
    combinedDidResolver.addResolver(ethrResolver);

    expect(combinedDidResolver.getResolvers().length).toEqual(1);
    let resolvedDID = await combinedDidResolver.resolveDidDocumet(did);

    expect(resolvedDID.id).toEqual(did);
  });
  test("b. ability to add KeyDidResolver and resolve a DID", async () => {
    let did = TD_DID_DOCS.key_2018_1.didDocument.id;
    let combinedDidResolver = new CombinedDidResolver("");
    let keyResolver = new KeyDidResolver("key");
    combinedDidResolver.addResolver(keyResolver);

    expect(combinedDidResolver.getResolvers().length).toEqual(1);
    let resolvedDID = await combinedDidResolver.resolveDidDocumet(did);

    expect(resolvedDID.id).toEqual(did);
  });
  test("c. ability to add multiple resolvers and resolve a DID", async () => {
    let combinedDidResolver = new CombinedDidResolver("");
    let didKey = TD_DID_DOCS.key_2018_1.didDocument.id; //did:key
    let didEthr = TD_DID_DOCS.ethr_rinkeby_1.didDocument.id; //did:ethr

    let keyResolver = new KeyDidResolver("key");
    let ethrResolver = new EthrDidResolver("ethr");
    combinedDidResolver.addResolver(keyResolver);
    combinedDidResolver.addResolver(ethrResolver);

    expect(combinedDidResolver.getResolvers().length).toEqual(2);
    let resolvedDIDKey = await combinedDidResolver.resolveDidDocumet(didKey);
    let resolvedDIDEthr = await combinedDidResolver.resolveDidDocumet(didEthr);

    expect(resolvedDIDKey.id).toEqual(didKey);
    expect(resolvedDIDEthr.id).toEqual(didEthr);
  });
});
