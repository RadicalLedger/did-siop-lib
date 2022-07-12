import { ALGORITHMS, KEY_FORMATS } from "./../src/core/globals";
import { sign } from "../src/core/jwt";
import {
  getBasicJWT,
  getModifiedJWT,
  getModifiedJWTSigned,
  claims,
} from "./common.spec.resources";
import { TD_DID_DOCS } from "./data/did-docs.testdata";

let testDidDoc = TD_DID_DOCS.ethr_rinkeby_1.didDocument;
let testDID = TD_DID_DOCS.ethr_rinkeby_1.didDocument.id;
let testKeyInfo = TD_DID_DOCS.ethr_rinkeby_1.keys[0];

export const siginingInfo = {
  alg: ALGORITHMS["ES256K"],
  key: testKeyInfo.privateKey,
  kid: testDidDoc.verificationMethod[1].id,
  format: KEY_FORMATS.HEX,
};

const jwtBasicGoodDecoded = getBasicJWT(
  testDidDoc.verificationMethod[1].id,
  testDID,
  testDID
);

const jwtBasicGoodEncoded = sign(jwtBasicGoodDecoded, siginingInfo);
const jwt_uri = "http://localhost/requestJWT";

export const TD_BASIC_JWT = {
  decoded: jwtBasicGoodDecoded,
  encoded: jwtBasicGoodEncoded,
};

const signedJWTs = {
  good: {
    jwtWithClaims: getModifiedJWTSigned(
      TD_BASIC_JWT.decoded,
      siginingInfo,
      true,
      "claims",
      claims.good
    ),
  },
  bad: {
    jwtBadNoKid: getModifiedJWTSigned(
      TD_BASIC_JWT.decoded,
      siginingInfo,
      false,
      "kid"
    ),
    jwtBadNoIss: getModifiedJWTSigned(
      TD_BASIC_JWT.decoded,
      siginingInfo,
      true,
      "iss"
    ),
    jwtBadNoScope: getModifiedJWTSigned(
      TD_BASIC_JWT.decoded,
      siginingInfo,
      true,
      "scope"
    ),
    jwtBadIncorrectScope: getModifiedJWTSigned(
      TD_BASIC_JWT.decoded,
      siginingInfo,
      true,
      "scope",
      "xxxxx"
    ),
    jwtBadNoRegistration: getModifiedJWTSigned(
      TD_BASIC_JWT.decoded,
      siginingInfo,
      true,
      "registration"
    ),
    jwtBadInvalidClaims: getModifiedJWTSigned(
      TD_BASIC_JWT.decoded,
      siginingInfo,
      true,
      "registration"
    ),
    jwtBadClaimsNoVPToken: getModifiedJWTSigned(
      TD_BASIC_JWT.decoded,
      siginingInfo,
      true,
      "claims",
      claims.bad
    ),
  },
};

export const requestJWT = {
  good: {
    basic: TD_BASIC_JWT.decoded,
    withVPToken: getModifiedJWT(
      TD_BASIC_JWT.decoded,
      true,
      "claims",
      claims.good
    ),
  },
  bad: {
    withVPToken: getModifiedJWT(
      TD_BASIC_JWT.decoded,
      true,
      "claims",
      claims.bad
    ),
  },
};

export const TD_REQUESTS = {
  good: {
    requestGoodEmbeddedJWT:
      "openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid&request=" +
      TD_BASIC_JWT.encoded,
    requestGoodUriJWT:
      "openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid&request_uri=" +
      jwt_uri,
    requestGoodWithClaims:
      "openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid&request=" +
      signedJWTs.good.jwtWithClaims,
  },
  bad: {
    requestBadProtocol:
      "opend://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid&request=" +
      TD_BASIC_JWT.encoded,
    requestBadNoSlashes:
      "openid:?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid&request=" +
      TD_BASIC_JWT.encoded,
    requestBadNoResponseType:
      "openid://?response_tye=id_token&client_id=https://rp.example.com/cb&scope=openid&request=" +
      TD_BASIC_JWT.encoded,
    requestBadIncorrectResponseType:
      "openid://?response_type=id_toke&client_id=https://rp.example.com/cb&scope=openid&request=" +
      TD_BASIC_JWT.encoded,
    requestBadNoClientId:
      "openid://?response_type=id_token&client_i=https://rp.example.com/cb&scope=openid&request=" +
      TD_BASIC_JWT.encoded,
    requestBadNoScope:
      "openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openi&request=" +
      TD_BASIC_JWT.encoded,
    requestBadNoScopeOpenId:
      "openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=did_authn&request=" +
      TD_BASIC_JWT.encoded,
    requestBadNoScopeDidAuthN:
      "openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid&request=" +
      TD_BASIC_JWT.encoded,
    requestBadNoJWT:
      "openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid&request=",
    requestBadNoJWTUri:
      "openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid&request_uri=",
    requestBadIncorrectJWTUri:
      "openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid&request_uri=http://localhost/incorrectRequestJWT",
    requestBadJWTNoKid:
      "openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid&request=" +
      signedJWTs.bad.jwtBadNoKid,
    requestBadJWTNoIss:
      "openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid&request=" +
      signedJWTs.bad.jwtBadNoIss,
    requestBadJWTNoScope:
      "openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid&request=" +
      signedJWTs.bad.jwtBadNoScope,
    requestBadJWTIncorrectScope:
      "openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid&request=" +
      signedJWTs.bad.jwtBadIncorrectScope,
    requestBadJWTNoRegistration:
      "openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid&request=" +
      signedJWTs.bad.jwtBadNoRegistration,
    requestBadJWTClaimsNoVPToken:
      "openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid&request=" +
      signedJWTs.bad.jwtBadClaimsNoVPToken,
  },
  components: {
    signingInfo: siginingInfo,
    rp: {
      did: testDID,
      redirect_uri: "https://my.rp.com/cb",
      registration: {
        jwks_uri:
          "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
        id_token_signed_response_alg: ["ES256K", "ES256K-R", "EdDSA", "RS256"],
      },
    },
    options: {
      state: "af0ifjsldkj",
      nonce: "n-0S6_WzA2Mj",
      response_mode: "form_post",
    },
    optionsWithClaims: {
      state: "af0ifjsldkj",
      nonce: "n-0S6_WzA2Mj",
      response_mode: "form_post",
      claims: claims.good,
    },
  },
};
