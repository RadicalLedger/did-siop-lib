import { EthrDidResolver } from "../../src/core/identity/resolvers";
import { TD_DID_DOCS } from "./did-docs.testdata";

export const PROVIDER_TD = {
  rp: {
    ...TD_DID_DOCS.ethr_rinkeby_1,
    resolver: new EthrDidResolver("ethr"),
  },
};
