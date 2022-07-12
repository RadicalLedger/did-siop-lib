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

// export const claims = {
//   good: {
//     id_token: {
//       email: null,
//     },
//     vp_token: {
//       presentation_definition: {
//         id: "vp token example",
//         input_descriptors: [
//           {
//             id: "id card credential",
//             format: {
//               ldp_vc: {
//                 proof_type: ["Ed25519Signature2018"],
//               },
//             },
//             constraints: {
//               fields: [
//                 {
//                   path: ["$.type"],
//                   filter: {
//                     type: "string",
//                     pattern: "IDCardCredential",
//                   },
//                 },
//               ],
//             },
//           },
//         ],
//       },
//     },
//   },
//   bad: {
//     id_token: {
//       email: null,
//     },
//     vp_token: {},
//   },
// };

const keyPair = {
  privateKey: {
    alg: ALGORITHMS["ES256K"],
    key: testKeyInfo.privateKey,
    kid: testDidDoc.verificationMethod[1].id,
    format: KEY_FORMATS.HEX,
  },
  publicKey: {
    alg: ALGORITHMS["ES256K"],
    key: testKeyInfo.publicKey,
    kid: testDidDoc.verificationMethod[1].id,
    format: KEY_FORMATS.HEX,
  },
};

const jwtBasicGoodDecoded = getBasicJWT(
  testDidDoc.verificationMethod[1].id,
  testDID,
  testDID
);

const jwtBasicGoodEncoded = sign(jwtBasicGoodDecoded, keyPair.privateKey);
const jwt_uri = "http://localhost/requestJWT";

export const basicJWT = {
  decoded: jwtBasicGoodDecoded,
  encoded: jwtBasicGoodEncoded,
};

export const signedJWTs = {
  good: {
    jwtWithClaims: getModifiedJWTSigned(
      basicJWT.decoded,
      keyPair.privateKey,
      true,
      "claims",
      claims.good
    ),
  },
  bad: {
    jwtBadNoKid: getModifiedJWTSigned(
      basicJWT.decoded,
      keyPair.privateKey,
      false,
      "kid"
    ),
    jwtBadNoIss: getModifiedJWTSigned(
      basicJWT.decoded,
      keyPair.privateKey,
      true,
      "iss"
    ),
    jwtBadNoScope: getModifiedJWTSigned(
      basicJWT.decoded,
      keyPair.privateKey,
      true,
      "scope"
    ),
    jwtBadIncorrectScope: getModifiedJWTSigned(
      basicJWT.decoded,
      keyPair.privateKey,
      true,
      "scope",
      "xxxxx"
    ),
    jwtBadNoRegistration: getModifiedJWTSigned(
      basicJWT.decoded,
      keyPair.privateKey,
      true,
      "registration"
    ),
    jwtBadInvalidClaims: getModifiedJWTSigned(
      basicJWT.decoded,
      keyPair.privateKey,
      true,
      "registration"
    ),
    jwtBadClaimsNoVPToken: getModifiedJWTSigned(
      basicJWT.decoded,
      keyPair.privateKey,
      true,
      "claims",
      claims.bad
    ),
  },
};

export const requestJWT = {
  good: {
    basic: basicJWT.decoded,
    withVPToken: getModifiedJWT(basicJWT.decoded, true, "claims", claims.good),
  },
  bad: {
    withVPToken: getModifiedJWT(basicJWT.decoded, true, "claims", claims.bad),
  },
};

export const requests = {
  good: {
    requestGoodEmbeddedJWT:
      "openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid&request=" +
      basicJWT.encoded,
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
      basicJWT.encoded,
    requestBadNoSlashes:
      "openid:?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid&request=" +
      basicJWT.encoded,
    requestBadNoResponseType:
      "openid://?response_tye=id_token&client_id=https://rp.example.com/cb&scope=openid&request=" +
      basicJWT.encoded,
    requestBadIncorrectResponseType:
      "openid://?response_type=id_toke&client_id=https://rp.example.com/cb&scope=openid&request=" +
      basicJWT.encoded,
    requestBadNoClientId:
      "openid://?response_type=id_token&client_i=https://rp.example.com/cb&scope=openid&request=" +
      basicJWT.encoded,
    requestBadNoScope:
      "openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openi&request=" +
      basicJWT.encoded,
    requestBadNoScopeOpenId:
      "openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=did_authn&request=" +
      basicJWT.encoded,
    requestBadNoScopeDidAuthN:
      "openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid&request=" +
      basicJWT.encoded,
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
    signingInfo: {
      alg: ALGORITHMS["ES256K"],
      key: testKeyInfo.privateKey,
      kid: testDidDoc.verificationMethod[1].id,
      format: KEY_FORMATS.HEX,
    },
    rp: {
      did: testDID,
      redirect_uri: "https://my.rp.com/cb",
      registration: {
        jwks_uri:
          "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
        id_token_signed_response_alg: ["ES256K", "EdDSA", "RS256"],
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
