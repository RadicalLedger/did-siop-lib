import { ERROR_RESPONSES } from "../src/core/error-response";
import { CRYPTO_SUITES } from "../src/core/globals";
import { KeyDidResolver } from "../src/core/identity/resolvers/did-resolver-key";
import { EthrDidResolver } from "../src/core/identity/resolvers/did-resolver-ethr";
import { JWTObject } from "../src/core/jwt";
import { Provider, ERRORS as ProviderErrors } from "../src/core/provider";
import { RP, ERRORS as RPErrors } from "../src/core/rp";
import nock from "nock";
import { TD_DID_DOCS } from "./data/did-docs.testdata";
import { TD_BASIC_JWT, TD_REQUESTS } from "./data/request.testdata";
import { tokenData, getModifiedJWT } from "./common.spec.resources";
import { VPData } from "../src/core/claims";

let userDidDoc = TD_DID_DOCS.ethr_rinkeby_2.didDocument;
let userDID = TD_DID_DOCS.ethr_rinkeby_2.didDocument.id;
let userPrivateKeyHex = TD_DID_DOCS.ethr_rinkeby_2.keys[0].privateKey;
let userKid = TD_DID_DOCS.ethr_rinkeby_2.didDocument.verificationMethod[1].id;

let rpDidDoc = TD_DID_DOCS.ethr_rinkeby_1.didDocument;
let rpDID = TD_DID_DOCS.ethr_rinkeby_1.didDocument.id;
let rpPrivateKey = TD_DID_DOCS.ethr_rinkeby_1.keys[0].privateKey;
let rpKid = TD_DID_DOCS.ethr_rinkeby_1.didDocument.verificationMethod[1].id;

let rpRedirectURI = TD_REQUESTS.components.rp.redirect_uri;
let rpRegistrationMetaData = TD_REQUESTS.components.rp.registration;
let requestObj: JWTObject = TD_BASIC_JWT.decoded;

// Prepare  the reqiest for RP.generateRequest() without any parameters
requestObj = getModifiedJWT(TD_BASIC_JWT.decoded, true, "nonce", null); // Remove nonce
requestObj = getModifiedJWT(requestObj, true, "response_mode", null); // Remove response_mode
requestObj = getModifiedJWT(requestObj, true, "state", null); // // Remove state

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
      TD_REQUESTS.components.optionsWithClaims
    );
    let requestJWTDecoded = await provider.validateRequest(request);
    expect(requestJWTDecoded).toMatchObject(requestObj);

    let response = await provider.generateResponse(requestJWTDecoded.payload);
    let responseJWTDecoded = await rp.validateResponse(response, {
      redirect_uri: rpRedirectURI,
      isExpirable: true,
      nonce: TD_REQUESTS.components.optionsWithClaims.nonce,
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
      TD_REQUESTS.components.optionsWithClaims
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
        nonce: TD_REQUESTS.components.optionsWithClaims.nonce,
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
      await provider.validateRequest(TD_REQUESTS.bad.requestBadJWTNoIss);
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
