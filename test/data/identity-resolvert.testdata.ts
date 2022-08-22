import {
  EthrDidResolver,
  KeyDidResolver,
} from "../../src/core/identity/resolvers";
import { TD_DID_DOCS } from "./did-docs.testdata";

export const didDocs = {
  all: [
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
  ],
  ethrDidDoc: {
    ...TD_DID_DOCS.ethr_rinkeby_1,
  },
  keyDidDoc: {
    ...TD_DID_DOCS.key_2018_1,
  },
  resolvers: [new EthrDidResolver("ethr"), new KeyDidResolver("key")],
};
