import {
  EthrDidResolver,
  KeyDidResolver,
} from "../../src/core/identity/resolvers";
import { TD_DID_DOCS } from "./did-docs.testdata";

export const defaultResolver = TD_DID_DOCS.ethr_rinkeby_1;
export const specificResolvers = [
  {
    tag: "ethr did resolver",
    ...TD_DID_DOCS.ethr_rinkeby_1,
    resolver: new EthrDidResolver("ethr"),
  },
  {
    tag: "key did resolver, @digitalbazaar/ed25519-verification-key-2018",
    ...TD_DID_DOCS.key_2018_1,
    resolver: new KeyDidResolver(
      "key",
      "@digitalbazaar/ed25519-verification-key-2018"
    ),
  },
  {
    tag: "key did resolver, @digitalbazaar/ed25519-verification-key-2020",
    ...TD_DID_DOCS.key_2018_2,
    resolver: new KeyDidResolver(
      "key",
      "@digitalbazaar/ed25519-verification-key-2020"
    ),
  },
];
