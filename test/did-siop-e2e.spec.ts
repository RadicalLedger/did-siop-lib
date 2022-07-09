import { ERROR_RESPONSES } from "../src/core/error-response";
import { CRYPTO_SUITES } from "../src/core/globals";
import { KeyDidResolver } from "../src/core/identity/resolvers/did-resolver-key";
import { EthrDidResolver } from "../src/core/identity/resolvers/did-resolver-ethr";
import { JWTObject } from "../src/core/jwt";
import { Provider, ERRORS as ProviderErrors } from "../src/core/provider";
import { RP, ERRORS as RPErrors } from "../src/core/rp";
import nock from "nock";
import { TD_DID_DOCS } from "./data/did-docs.testdata";
import { requests } from "./request.spec.resources";
import { tokenData } from "./common.spec.resources";
import { VPData } from "../src/core/claims";

let userDidDoc = TD_DID_DOCS.ethr_rinkeby_1.didDocument;
let userDID = TD_DID_DOCS.ethr_rinkeby_1.didDocument.id;
let userPrivateKeyHex = TD_DID_DOCS.ethr_rinkeby_1.keys[0].privateKey;
let userKid = TD_DID_DOCS.ethr_rinkeby_1.didDocument.verificationMethod[1].id;

let rpDidDoc = TD_DID_DOCS.ethr_rinkeby_2.didDocument;
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
    scope: "openid",
    client_id: rpDID,
    registration: {
      jwks_uri:
        "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
      id_token_signed_response_alg: ["ES256K", "ES256K-R", "EdDSA", "RS256"],
    },
  },
};

let badRequest =
  "openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid&request=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiIsImtpZCI6ImRpZDpldGhyOjB4QjA3RWFkOTcxN2I0NEI2Y0Y0MzljNDc0MzYyYjlCMDg3N0NCQkY4MyNvd25lciJ9.eyJyZXNwb25zZV90eXBlIjoiaWRfdG9rZW4iLCJjbGllbnRfaWQiOiJodHRwczovL215LnJwLmNvbS9jYiIsInNjb3BlIjoib3BlbmlkIGRpZF9hdXRobiIsInN0YXRlIjoiYWYwaWZqc2xka2oiLCJub25jZSI6Im4tMFM2X1d6QTJNaiIsInJlc3BvbnNlX21vZGUiOiJmb3JtX3Bvc3QiLCJyZWdpc3RyYXRpb24iOnsiandrc191cmkiOiJodHRwczovL3VuaXJlc29sdmVyLmlvLzEuMC9pZGVudGlmaWVycy9kaWQ6ZXhhbXBsZToweGFiO3RyYW5zZm9ybS1rZXlzPWp3a3MiLCJpZF90b2tlbl9zaWduZWRfcmVzcG9uc2VfYWxnIjpbIkVTMjU2SyIsIkVkRFNBIiwiUlMyNTYiXX19.mXh9VLcxzHFt3D1EFRQm0xDfPB7P4YbnZX2u8Lm46mU4TIbBDqx49tyVMeAx2BCRORAN__JXS2U4NpVheAaX2wA";

describe("007.01 DID SIOP using did:ethr method DIDs", function () {
  beforeEach(() => {
    nock("https://uniresolver.io/1.0/identifiers")
      .persist()
      .get("/" + rpDID)
      .reply(200, rpDidDoc)
      .get("/" + userDID)
      .reply(200, userDidDoc);
  });
  test("a. DID SIOP end to end functions testing - expect truthy", async () => {
    jest.setTimeout(30000);

    let rp = await RP.getRP(rpRedirectURI, rpDID, rpRegistrationMetaData);
    let kid = rp.addSigningParams(rpPrivateKey);
    expect(kid).toEqual(rpKid);

    let provider = await Provider.getProvider(userDID);
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

  test("b. DID SIOP e2e functions testing with VPs- expect truthy", async () => {
    jest.setTimeout(30000);

    let rp = await RP.getRP(rpRedirectURI, rpDID, rpRegistrationMetaData);
    let kid = rp.addSigningParams(rpPrivateKey);
    expect(kid).toEqual(rpKid);

    let provider = await Provider.getProvider(userDID);
    kid = provider.addSigningParams(userPrivateKeyHex);
    expect(kid).toEqual(userKid);

    let request = await rp.generateRequest(
      requests.components.optionsWithClaims
    );
    let requestJWTDecoded = await provider.validateRequest(request);
    expect(requestJWTDecoded).toMatchObject(requestObj);

    let response = await provider.generateResponse(requestJWTDecoded.payload);
    let responseJWTDecoded = await rp.validateResponse(response, {
      redirect_uri: rpRedirectURI,
      isExpirable: true,
      nonce: requests.components.optionsWithClaims.nonce,
    });
    expect(responseJWTDecoded).toHaveProperty("header");
    expect(responseJWTDecoded).toHaveProperty("payload");
  });

  test("c. DID SIOP e2e functions testing with VPs and Validate VPs- expect truthy", async () => {
    jest.setTimeout(30000);

    let rp = await RP.getRP(rpRedirectURI, rpDID, rpRegistrationMetaData);
    let kid = rp.addSigningParams(rpPrivateKey);
    expect(kid).toEqual(rpKid);

    let provider = await Provider.getProvider(userDID);
    kid = provider.addSigningParams(userPrivateKeyHex);
    expect(kid).toEqual(userKid);

    let request = await rp.generateRequest(
      requests.components.optionsWithClaims
    );
    let requestJWTDecoded = await provider.validateRequest(request);
    expect(requestJWTDecoded).toMatchObject(requestObj);

    let vps: VPData = {
      vp_token: tokenData.good.singleVP.vp_token,
      _vp_token: tokenData.good.singleVP.id_token._vp_token,
    };

    let siopTokenEncoded = await provider.generateResponseWithVPData(
      requestJWTDecoded.payload,
      5000,
      vps
    );
    let siopTokenObjects = await rp.validateResponseWithVPData(
      siopTokenEncoded,
      {
        redirect_uri: rpRedirectURI,
        isExpirable: true,
        nonce: requests.components.optionsWithClaims.nonce,
      }
    );
    expect(siopTokenObjects).toHaveProperty("id_token");
    expect(siopTokenObjects).toHaveProperty("vp_token");
  });

  test("d. DID SIOP end to end functions testing - expect falsy", async () => {
    jest.setTimeout(30000);

    let rp = await RP.getRP(rpRedirectURI, rpDID, rpRegistrationMetaData);
    rp.addSigningParams(rpPrivateKey);

    let provider = await Provider.getProvider(userDID);
    provider.addSigningParams(userPrivateKeyHex);

    rp.removeSigningParams(rpKid);
    let requestPromise = rp.generateRequest();
    expect(requestPromise).rejects.toEqual(new Error(RPErrors.NO_SIGNING_INFO));

    provider.removeSigningParams(userKid);
    let responsePromise = provider.generateResponse(requestObj.payload);
    expect(responsePromise).rejects.toEqual(
      new Error(ProviderErrors.NO_SIGNING_INFO)
    );
  });
  test("e. DID SIOP end to end functions testing - Error Response", async () => {
    jest.setTimeout(30000);

    let rp = await RP.getRP(rpRedirectURI, rpDID, rpRegistrationMetaData);
    rp.addSigningParams(rpPrivateKey);

    let provider = await Provider.getProvider(userDID);
    provider.addSigningParams(userPrivateKeyHex);

    let requestValidationError = new Error("Unknown error");
    try {
      await provider.validateRequest(badRequest);
    } catch (err) {
      requestValidationError = err;
    }
    let errorResponse = provider.generateErrorResponse(
      requestValidationError.message
    );
    let errorResponseDecoded = await rp.validateResponse(errorResponse);
    expect(errorResponseDecoded).toEqual(
      ERROR_RESPONSES.invalid_request_object.response
    );
  });
});

describe("007.02 DID SIOP using did:key method DIDs : crypto suite Ed25519VerificationKey2018", function () {
  test("a. end to end functions testing ", async () => {
    jest.setTimeout(30000);
    let keyResolv2018 = new KeyDidResolver(
      "key",
      CRYPTO_SUITES.Ed25519VerificationKey2018
    );
    let rp = await RP.getRP(
      rpRedirectURI,
      TD_DID_DOCS.key_2018_1.didDocument.id,
      rpRegistrationMetaData,
      undefined,
      [keyResolv2018]
    );
    let kid = rp.addSigningParams(TD_DID_DOCS.key_2018_1.keys[0].privateKey);
    expect(kid).toEqual(
      TD_DID_DOCS.key_2018_1.didDocument.verificationMethod[0].id
    );

    let provider = await Provider.getProvider(
      TD_DID_DOCS.key_2018_2.didDocument.id,
      undefined,
      [keyResolv2018]
    );
    kid = provider.addSigningParams(TD_DID_DOCS.key_2018_2.keys[0].privateKey);
    expect(kid).toEqual(
      TD_DID_DOCS.key_2018_2.didDocument.verificationMethod[0].id
    );

    let request = await rp.generateRequest();
    let requestJWTDecoded = await provider.validateRequest(request);

    let response = await provider.generateResponse(requestJWTDecoded.payload);
    let responseJWTDecoded = await rp.validateResponse(response, {
      redirect_uri: rpRedirectURI,
      isExpirable: true,
    });

    expect(responseJWTDecoded).toHaveProperty("header");
    expect(responseJWTDecoded).toHaveProperty("payload");
  });
});

describe("007.03 DID SIOP using did:key method DIDs : crypto suite Ed25519VerificationKey2020", function () {
  test("a. end to end functions testing ", async () => {
    jest.setTimeout(30000);
    let keyResolv2020 = new KeyDidResolver(
      "key",
      CRYPTO_SUITES.Ed25519VerificationKey2020
    );
    let rp = await RP.getRP(
      rpRedirectURI,
      TD_DID_DOCS.key_2020_1.didDocument.id,
      rpRegistrationMetaData,
      undefined,
      [keyResolv2020]
    );
    let kid = rp.addSigningParams(TD_DID_DOCS.key_2020_1.keys[0].privateKey);
    expect(kid).toEqual(
      TD_DID_DOCS.key_2020_1.didDocument.verificationMethod[0].id
    );

    let provider = await Provider.getProvider(
      TD_DID_DOCS.key_2020_1.didDocument.id,
      undefined,
      [keyResolv2020]
    );
    kid = provider.addSigningParams(TD_DID_DOCS.key_2020_1.keys[0].privateKey);
    expect(kid).toEqual(
      TD_DID_DOCS.key_2020_1.didDocument.verificationMethod[0].id
    );

    let request = await rp.generateRequest();
    let requestJWTDecoded = await provider.validateRequest(request);

    let response = await provider.generateResponse(requestJWTDecoded.payload);
    let responseJWTDecoded = await rp.validateResponse(response, {
      redirect_uri: rpRedirectURI,
      isExpirable: true,
    });

    expect(responseJWTDecoded).toHaveProperty("header");
    expect(responseJWTDecoded).toHaveProperty("payload");
  });
});

describe("007.04 DID SIOP using did:ethr method DIDs and did:ethr resover", function () {
  beforeEach(() => {
    nock("https://uniresolver.io/1.0/identifiers")
      .persist()
      .get("/" + rpDID)
      .reply(200, rpDidDoc)
      .get("/" + userDID)
      .reply(200, userDidDoc);
  });
  test("a. DID SIOP end to end functions testing - expect truthy", async () => {
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

    let provider = await Provider.getProvider(userDID);
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
