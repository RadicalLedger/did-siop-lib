import { ERROR_RESPONSES } from "../src/core/error-response";
import { JWTObject } from "../src/core/jwt";
import { ERRORS as ProviderErrors, Provider } from "../src/core/provider";
import { ERRORS as RPErrors, RP } from "../src/core/rp";
import nock from "nock";
import { TD_BASIC_JWT, TD_REQUESTS } from "./data/request.testdata";
import { getModifiedJWT, tokenData } from "./data/common.testdata";
import { VPData } from "../src/core/claims";
import { DID_SIOP_E2E_TD } from "./data/did-siop-e2e.testdata";

let rpRedirectURI = TD_REQUESTS.components.rp.redirect_uri;
let rpRegistrationMetaData = TD_REQUESTS.components.rp.registration;
let requestObj: JWTObject = TD_BASIC_JWT.decoded;

// Prepare  the reqiest for RP.generateRequest() without any parameters
requestObj = getModifiedJWT(TD_BASIC_JWT.decoded, true, "nonce", null); // Remove nonce
requestObj = getModifiedJWT(requestObj, true, "response_mode", null); // Remove response_mode
requestObj = getModifiedJWT(requestObj, true, "state", null); // // Remove state

//Set the default timeout interval to 30000 ms for all tests and before/after hooks
jest.setTimeout(30000);

describe.each(DID_SIOP_E2E_TD.MULTIPLE_DIDS_TD)(
  "007.01 DID SIOP using did ($tag)",
  ({ rp, user }) => {
    // const userDidDoc = data.user.didDocument;
    const userDID = user.didDocument.id;
    const userPrivateKeyHex = user.keys[0].privateKey;
    const userKid = user.didDocument.verificationMethod[0].id;
    const userDidDoc = user.didDocument;

    // const rpDidDoc = data.rp.didDocument;
    const rpDID = rp.didDocument.id;
    const rpPrivateKey = rp.keys[0].privateKey;
    const rpKid = rp.didDocument.verificationMethod[0].id;
    const rpDidDoc = rp.didDocument;

    const rpResolver = rp.resolver;
    const userResolver = user.resolver;

    beforeEach(() => {
      nock("https://uniresolver.io/1.0/identifiers")
        .persist()
        .get("/" + rpDID)
        .reply(200, rpDidDoc)
        .get("/" + userDID)
        .reply(200, userDidDoc);
    });

    test("a. DID SIOP end to end functions testing - expect truthy ", async () => {
      let rp = await RP.getRP(
        rpRedirectURI,
        rpDID,
        rpRegistrationMetaData,
        undefined,
        [rpResolver]
      );

      let kid = rp.addSigningParams(rpPrivateKey);
      expect(kid).toEqual(rpKid);

      const provider = await Provider.getProvider(userDID, undefined, [
        userResolver,
      ]);
      kid = provider.addSigningParams(userPrivateKeyHex);
      expect(kid).toEqual(userKid);

      const request = await rp.generateRequest();
      const requestJWTDecoded = await provider.validateRequest(request);

      const response = await provider.generateResponse(
        requestJWTDecoded.payload
      );
      const responseJWTDecoded = await rp.validateResponse(response, {
        redirect_uri: rpRedirectURI,
        isExpirable: true,
      });

      expect(responseJWTDecoded).toHaveProperty("header");
      expect(responseJWTDecoded).toHaveProperty("payload");
    });

    test("d. DID SIOP end to end functions testing - expect falsy", async () => {
      const rp = await RP.getRP(
        rpRedirectURI,
        rpDID,
        rpRegistrationMetaData,
        undefined,
        [rpResolver]
      );
      rp.addSigningParams(rpPrivateKey);

      const provider = await Provider.getProvider(userDID, undefined, [
        userResolver,
      ]);
      provider.addSigningParams(userPrivateKeyHex);

      rp.removeSigningParams(rpKid);
      let requestPromise = rp.generateRequest();
      await expect(requestPromise).rejects.toEqual(
        new Error(RPErrors.NO_SIGNING_INFO)
      );

      provider.removeSigningParams(userKid);
      let responsePromise = provider.generateResponse(requestObj.payload);
      await expect(responsePromise).rejects.toEqual(
        new Error(ProviderErrors.NO_SIGNING_INFO)
      );
    });
  }
);

describe("007.01 DID SIOP using did:ethr method DIDs", function () {
  const userDidDoc = DID_SIOP_E2E_TD.SINGLE_DID_TD.user.didDocument;
  const userDID = DID_SIOP_E2E_TD.SINGLE_DID_TD.user.didDocument.id;
  const userPrivateKeyHex =
    DID_SIOP_E2E_TD.SINGLE_DID_TD.user.keys[0].privateKey;
  const userKid =
    DID_SIOP_E2E_TD.SINGLE_DID_TD.user.didDocument.verificationMethod[1].id;

  const rpDidDoc = DID_SIOP_E2E_TD.SINGLE_DID_TD.rp.didDocument;
  const rpDID = DID_SIOP_E2E_TD.SINGLE_DID_TD.rp.didDocument.id;
  const rpPrivateKey = DID_SIOP_E2E_TD.SINGLE_DID_TD.rp.keys[0].privateKey;
  const rpKid =
    DID_SIOP_E2E_TD.SINGLE_DID_TD.rp.didDocument.verificationMethod[1].id;

  beforeEach(() => {
    nock("https://uniresolver.io/1.0/identifiers")
      .persist()
      .get("/" + rpDID)
      .reply(200, rpDidDoc)
      .get("/" + userDID)
      .reply(200, userDidDoc);
  });
  test("a. DID SIOP end to end functions testing - expect truthy", async () => {
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
    let rp = await RP.getRP(rpRedirectURI, rpDID, rpRegistrationMetaData);
    rp.addSigningParams(rpPrivateKey);

    let provider = await Provider.getProvider(userDID);
    provider.addSigningParams(userPrivateKeyHex);

    let requestValidationError = new Error("Unknown error");
    try {
      await provider.validateRequest(TD_REQUESTS.bad.requestBadJWTNoIss);
    } catch (err: any) {
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
