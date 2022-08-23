import { CombinedDidResolver } from "../src/core/identity/resolvers";
import { IDENTITY_RESOLVER_TD } from "./data/identity-resolver.testdata";

//Set the default timeout interval to 17000 ms for all tests and before/after hooks
jest.setTimeout(17000);

describe.each(IDENTITY_RESOLVER_TD.dids)(
  "001.01 CombinedDidResolver Functionalities with default resolver with did $tag",
  ({ didDocument }) => {
    test("a. ability to resolve using default resolver", async () => {
      const did = didDocument.id;
      const combinedDidResolver = new CombinedDidResolver("all");
      const resolvedDID = await combinedDidResolver.resolveDidDocumet(did);
      expect(resolvedDID.id).toEqual(did);
    });
  }
);

describe("001.02 CombinedDidResolver Functionalities with given Resolver ", function () {
  describe.each(IDENTITY_RESOLVER_TD.resolvers)(
    "a. ability to add $tag resolver and resolve a DID",
    ({ resolver, didDocument }) => {
      test("", async () => {
        const did = didDocument.id;
        const combinedDidResolver = new CombinedDidResolver("");
        combinedDidResolver.addResolver(resolver);

        expect(combinedDidResolver.getResolvers().length).toEqual(1);
        const resolvedDID = await combinedDidResolver.resolveDidDocumet(did);

        expect(resolvedDID.id).toEqual(did);
      });
    }
  );
  test("c. ability to add multiple resolvers and resolve a DID", async () => {
    const combinedDidResolver = new CombinedDidResolver("");
    const resolvers = IDENTITY_RESOLVER_TD.resolvers;
    resolvers.forEach((r) => combinedDidResolver.addResolver(r.resolver));

    expect(combinedDidResolver.getResolvers().length).toEqual(resolvers.length);
    for (const r of resolvers) {
      const resolvedDIDKey = await combinedDidResolver.resolveDidDocumet(
        r.didDocument.id
      );
      expect(resolvedDIDKey.id).toEqual(r.didDocument.id);
    }
  });
});
