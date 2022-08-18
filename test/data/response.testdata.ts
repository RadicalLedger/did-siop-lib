import { EthrDidResolver } from "../../src/core/identity/resolvers";
import { TD_DID_DOCS } from "./did-docs.testdata";

export const rp = {
  ...TD_DID_DOCS.ethr_rinkeby_2,
  resolver: new EthrDidResolver("ethr"),
};

export const user = {
  ...TD_DID_DOCS.ethr_rinkeby_1,
  resolver: new EthrDidResolver("ethr"),
};
