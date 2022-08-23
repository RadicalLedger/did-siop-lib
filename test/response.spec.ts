import { ERROR_RESPONSES } from "../src/core/error-response";
import { DidSiopResponse } from "../src/core/response";
import { Identity } from "../src/core/identity";
import { SIOPTokensEcoded, VPData } from "../src/core/claims";
import { toJWTObject } from "../src/core/jwt";
import nock from "nock";
import { siginingInfo, requestJWT } from "./data/request.testdata";
import { checkParamsOfGoodDecoded, tokenData } from "./data/common.testdata";
import { RESPONSE_TD } from "./data/response.testdata";

const userDidDoc = RESPONSE_TD.user.didDocument;
const userDID = userDidDoc.id;
const userResolver = RESPONSE_TD.user.resolver;

const rpDidDoc = RESPONSE_TD.rp.didDocument;
const rpDID = rpDidDoc.id;

//Set the default timeout interval to 30000 ms for all tests and before/after hooks
jest.setTimeout(30000);

describe("004.01 Response with the id_token", function () {
  beforeEach(() => {
    nock("https://uniresolver.io/1.0/identifiers")
      .persist()
      .get("/" + rpDID)
      .reply(200, rpDidDoc)
      .get("/" + userDID)
      .reply(200, userDidDoc);
  });
  test("a. with basic info : generation and validation", async () => {
    let user = new Identity();
    await user.resolve(userDID);

    let response = await DidSiopResponse.generateResponse(
      requestJWT.good.basic.payload,
      siginingInfo,
      user,
      30000
    );
    let validity = await DidSiopResponse.validateResponse(
      response,
      checkParamsOfGoodDecoded
    );
    expect(validity).toBeTruthy();

    let resJWT = toJWTObject(response);
    if (resJWT)
      expect(resJWT.payload.aud).toBe(
        requestJWT.good.basic.payload.redirect_uri
      );
  });
});

describe("004.02 Response validation for a request with a vp_token", function () {
  beforeEach(() => {
    nock("https://uniresolver.io/1.0/identifiers")
      .persist()
      .get("/" + rpDID)
      .reply(200, rpDidDoc)
      .get("/" + userDID)
      .reply(200, userDidDoc);
  });
  test("a. Valid token : generation and validation", async () => {
    let user = new Identity();
    await user.resolve(userDID);

    let response = await DidSiopResponse.generateResponse(
      requestJWT.good.withVPToken.payload,
      siginingInfo,
      user,
      30000
    );
    let validity = await DidSiopResponse.validateResponse(
      response,
      checkParamsOfGoodDecoded
    );
    expect(validity).toBeTruthy();
  });
  test("b. Invalid token : generation", async () => {
    let user = new Identity();
    await user.resolve(userDID);

    let validityPromise = DidSiopResponse.generateResponse(
      requestJWT.bad.withVPToken.payload,
      siginingInfo,
      user,
      30000
    );
    await expect(validityPromise).rejects.toEqual(
      ERROR_RESPONSES.vp_token_missing_presentation_definition.response.error
    );
  });
});

describe("004.03 Response generation and validation with vp_token data", function () {
  test("a. Valid vp_token & _vp_token should generate a valid response", async () => {
    let user = new Identity();
    await user.resolve(userDID);

    let vps: VPData = {
      vp_token: tokenData.good.singleVP.vp_token,
      _vp_token: tokenData.good.singleVP.id_token._vp_token,
    };

    let response: SIOPTokensEcoded =
      await DidSiopResponse.generateResponseWithVPData(
        requestJWT.good.withVPToken.payload,
        siginingInfo,
        user,
        30000,
        vps
      );
    let validity = await DidSiopResponse.validateResponse(
      response.id_token,
      checkParamsOfGoodDecoded
    );
    expect(validity).toBeTruthy();

    let validResponse = await DidSiopResponse.validateResponseWithVPData(
      response,
      checkParamsOfGoodDecoded
    );
    expect(validResponse).toBeTruthy();
  });

  test("b. Invalid vp_token : generation should raise an exception", async () => {
    let user = new Identity();
    await user.resolve(userDID);

    let bad_vp: VPData = {
      vp_token: tokenData.bad.singleVP.vp_token,
      _vp_token: tokenData.bad.singleVP.id_token._vp_token,
    };

    let response = DidSiopResponse.generateResponseWithVPData(
      requestJWT.good.withVPToken.payload,
      siginingInfo,
      user,
      30000,
      bad_vp
    );
    await expect(response).rejects.toEqual(
      ERROR_RESPONSES.vp_token_missing_verifiableCredential.err
    );
  });
});

describe("004.04 Response Generation/Validation with the id_token using specific Resolver (did:ethr)", function () {
  beforeEach(() => {
    nock("https://uniresolver.io/1.0/identifiers")
      .persist()
      .get("/" + rpDID)
      .reply(200, rpDidDoc)
      .get("/" + userDID)
      .reply(200, userDidDoc);
  });
  test("a. with basic info : generation and validation", async () => {
    let user = new Identity();

    await user.resolve(userDID);

    let response = await DidSiopResponse.generateResponse(
      requestJWT.good.basic.payload,
      siginingInfo,
      user,
      30000
    );
    let validity = await DidSiopResponse.validateResponse(
      response,
      checkParamsOfGoodDecoded,
      [userResolver]
    );
    expect(validity).toBeTruthy();

    let resJWT = toJWTObject(response);
    if (resJWT)
      expect(resJWT.payload.aud).toBe(
        requestJWT.good.basic.payload.redirect_uri
      );
  });
});
