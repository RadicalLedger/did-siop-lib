require("@babel/polyfill");
export { Provider } from "./core/provider";
export { RP } from "./core/rp";
export { DidDocument, Resolvers } from "./core/identity";
export {
  ALGORITHMS,
  KEY_FORMATS,
  KTYS,
  SIOP_METADATA_SUPPORTED,
  CRYPTO_SUITES,
} from "./core/globals";
export { JWTObject } from "./core/jwt";
export { CheckParams } from "./core/response";
export {
  SIOPError,
  SIOPErrorResponse,
  ERROR_RESPONSES,
} from "./core/error-response";
export { VPData, SIOPTokensEcoded, SIOPTokenObjects } from "./core/claims";
