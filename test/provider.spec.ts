import { JWTObject } from "../src/core/jwt";
import { TD_DID_DOCS } from "./data/did-docs.testdata";
import { RP } from "../src/core/rp";
import { Provider } from "../src/core/provider";
import { EthrDidResolver } from "../src/core/identity/resolvers/did-resolver-ethr";

let userDID = TD_DID_DOCS.ethr_rinkeby_1.didDocument.id;
let userPrivateKeyHex = TD_DID_DOCS.ethr_rinkeby_1.keys[0].privateKey;
let userKid = TD_DID_DOCS.ethr_rinkeby_1.didDocument.verificationMethod[1].id;

let rpDID = TD_DID_DOCS.ethr_rinkeby_2.didDocument.id;
let rpPrivateKey = TD_DID_DOCS.ethr_rinkeby_2.keys[0].privateKey;
let rpKid = TD_DID_DOCS.ethr_rinkeby_2.didDocument.verificationMethod[1].id;

let rpRedirectURI = "https://my.rp.com/cb";
let rpRegistrationMetaData = {
  jwks_uri:
    "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
  id_token_signed_response_alg: ["ES256K", "ES256K-R", "EdDSA", "RS256"],
};

let requestObj: JWTObject = {
  header: {
    alg: "ES256K",
    typ: "JWT",
    kid: rpKid,
  },
  payload: {
    iss: rpDID,
    response_type: "id_token",
    scope: "openid did_authn",
    client_id: rpDID,
    registration: {
      jwks_uri:
        "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
      id_token_signed_response_alg: ["ES256K", "ES256K-R", "EdDSA", "RS256"],
    },
  },
};

describe("006 Provider testing with dynamically added resolver", function () {
  test("a. with did:ethr resolver", async () => {
    jest.setTimeout(30000);

    let ethrResolver = new EthrDidResolver("ethr");

    let rp = await RP.getRP(
      rpRedirectURI,
      rpDID,
      rpRegistrationMetaData,
      undefined,
      [ethrResolver]
    );
    let kid = rp.addSigningParams(rpPrivateKey);
    expect(kid).toEqual(rpKid);

    let provider = await Provider.getProvider(userDID, undefined, [
      ethrResolver,
    ]);
    kid = provider.addSigningParams(userPrivateKeyHex);
    expect(kid).toEqual(userKid);

    let request = await rp.generateRequest();
    let requestJWTDecoded = await provider.validateRequest(request);
    expect(requestJWTDecoded).toMatchObject(requestObj);

    let response = await provider.generateResponse(requestJWTDecoded.payload);
    let responseJWTDecoded = await rp.validateResponse(response, {
      redirect_uri: rpRedirectURI,
      isExpirable: true,
    });
    expect(responseJWTDecoded).toHaveProperty("header");
    expect(responseJWTDecoded).toHaveProperty("payload");
  });
});
