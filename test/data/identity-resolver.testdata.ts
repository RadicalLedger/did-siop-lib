import {
  EthrDidResolver,
  KeyDidResolver,
} from "../../src/core/identity/resolvers";
import { TD_DID_DOCS } from "./did-docs.testdata";

export const dids = [
  {
    tag: "ethr",
    ...TD_DID_DOCS.ethr_rinkeby_1,
  },
  {
    tag: "key_2018",
    ...TD_DID_DOCS.key_2018_1,
  },
  {
    tag: "key_2020",
    ...TD_DID_DOCS.key_2020_1,
  },
];

export const resolvers = [
  {
    tag: "ethr",
    ...TD_DID_DOCS.ethr_rinkeby_1,
    resolver: new EthrDidResolver("ethr"),
  },
  {
    tag: "key",
    ...TD_DID_DOCS.key_2018_1,
    resolver: new KeyDidResolver("key"),
  },
];

export const IDENTITY_RESOLVER_TD = {
  resolvers,
  dids,
};
