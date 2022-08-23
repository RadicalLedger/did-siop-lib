import {
  EthrDidResolver,
  KeyDidResolver,
} from "../../src/core/identity/resolvers";
import { TD_DID_DOCS } from "./did-docs.testdata";

export const RP_TD = {
  didDocs: [
    {
      tag: "ethr",
      ...TD_DID_DOCS.ethr_rinkeby_2,
      resolver: new EthrDidResolver("ethr"),
    },
    {
      tag: "key_2018",
      ...TD_DID_DOCS.key_2018_2,
      resolver: new KeyDidResolver(
        "key",
        "@digitalbazaar/ed25519-verification-key-2018"
      ),
    },
    {
      tag: "key_2020",
      ...TD_DID_DOCS.key_2020_1,
      resolver: new KeyDidResolver(
        "key",
        "@digitalbazaar/ed25519-verification-key-2020"
      ),
    },
  ],
};
