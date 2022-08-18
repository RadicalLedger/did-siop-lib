import {
  EthrDidResolver,
  KeyDidResolver,
} from "../../src/core/identity/resolvers";
import { TD_DID_DOCS } from "./did-docs.testdata";

export const singleTD = {
  user: {
    ...TD_DID_DOCS.ethr_rinkeby_1,
    resolver: new EthrDidResolver("ethr"),
  },
  rp: {
    ...TD_DID_DOCS.ethr_rinkeby_2,
    resolver: new EthrDidResolver("ethr"),
  },
};

export const multipleTD = [
  {
    tag: "ethr",
    user: {
      ...TD_DID_DOCS.ethr_rinkeby_1,
      resolver: new EthrDidResolver("ethr"),
    },
    rp: {
      ...TD_DID_DOCS.ethr_rinkeby_2,
      resolver: new EthrDidResolver("ethr"),
    },
  },
  {
    tag: "key_2018",
    user: {
      ...TD_DID_DOCS.key_2018_1,
      resolver: new KeyDidResolver(
        "key",
        "@digitalbazaar/ed25519-verification-key-2018"
      ),
    },
    rp: {
      ...TD_DID_DOCS.key_2018_2,
      resolver: new KeyDidResolver(
        "key",
        "@digitalbazaar/ed25519-verification-key-2018"
      ),
    },
  },
  {
    tag: "key_2020",
    user: {
      ...TD_DID_DOCS.key_2020_1,
      resolver: new KeyDidResolver(
        "key",
        "@digitalbazaar/ed25519-verification-key-2020"
      ),
    },
    rp: {
      ...TD_DID_DOCS.key_2020_1,
      resolver: new KeyDidResolver(
        "key",
        "@digitalbazaar/ed25519-verification-key-2020"
      ),
    },
  },
];
