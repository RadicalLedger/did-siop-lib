import { ERROR_RESPONSES } from '../src/core/ErrorResponse';
import { DidSiopResponse } from '../src/core/Response';
import { Identity } from '../src/core/Identity';
import { SIOPTokensEcoded, VPData } from '../src/core/Claims';
import { SigningInfo, toJWTObject } from '../src/core/JWT';
// import { SigningInfo } from '../src/core/JWT';
import { ALGORITHMS, KEY_FORMATS } from '../src/core/globals';
import nock from 'nock';
import { requestJWT } from './response.spec.resources';
import {DID_TEST_RESOLVER_DATA_NEW as DIDS } from './did_doc.spec.resources'
import { tokenData } from './common.spec.resources';
import { EthrDidResolver } from '../src/core/Identity/Resolvers';

let userDidDoc  = DIDS[0].resolverReturn.didDocument;
let userDID     = DIDS[0].did;
let userKeyInfo = DIDS[0].keyInfo;

let rpDidDoc    = DIDS[1].resolverReturn.didDocument;
let rpDID       = DIDS[1].did;

let signing: SigningInfo = {
    alg: ALGORITHMS["ES256K"],
    kid: userDidDoc.verificationMethod[1].id,
    key: userKeyInfo.privateKey,
    format: KEY_FORMATS.HEX,
}

let checkParams = {
    redirect_uri: 'https://my.rp.com/cb',
    nonce: "n-0S6_WzA2Mj",
    validBefore: 30000,
    isExpirable: true,
}

describe("004.01 Response with the id_token", function () {
    beforeEach(() => {
        nock('https://uniresolver.io/1.0/identifiers').persist().get('/'+rpDID).reply(200, rpDidDoc).get('/'+userDID).reply(200, userDidDoc);
    });
    test("a. with basic info : generation and validation", async () => {
        jest.setTimeout(30000);
        let user = new Identity();
        await user.resolve(userDID)

        let response = await DidSiopResponse.generateResponse(requestJWT.good.basic.payload, signing, user, 30000);
        let validity = await DidSiopResponse.validateResponse(response, checkParams);
        expect(validity).toBeTruthy();
        
        let resJWT = toJWTObject(response);
        if (resJWT)
            expect(resJWT.payload.aud).toBe(requestJWT.good.basic.payload.redirect_uri);
    });
});

describe("004.02 Response validation for a request with a vp_token", function () {
    beforeEach(() => {
        nock('https://uniresolver.io/1.0/identifiers').persist().get('/'+rpDID).reply(200, rpDidDoc).get('/'+userDID).reply(200, userDidDoc);
    });
    test("a. Valid token : generation and validation", async () => {
        jest.setTimeout(30000);
        let user = new Identity();
        await user.resolve(userDID)

        let response = await DidSiopResponse.generateResponse(requestJWT.good.withVPToken.payload, signing, user, 30000);
        let validity = await DidSiopResponse.validateResponse(response, checkParams);
        expect(validity).toBeTruthy();
    });
    test("b. Invalid token : generation", async () => {
        jest.setTimeout(30000);
        let user = new Identity();
        await user.resolve(userDID)

        let validityPromise = DidSiopResponse.generateResponse(requestJWT.bad.withVPToken.payload, signing, user, 30000);
        await expect(validityPromise).rejects.toEqual(ERROR_RESPONSES.vp_token_missing_presentation_definition.response.error);
    });
});

describe("004.03 Response generation and validation with vp_token data", function () {
    test("a. Valid vp_token & _vp_token should generate a valid response", async () => {
        jest.setTimeout(30000);
        let user = new Identity();
        await user.resolve(userDID)

        let vps: VPData = {
            vp_token : tokenData.good.singleVP.vp_token,
            _vp_token : tokenData.good.singleVP.id_token._vp_token
        };

        let response:SIOPTokensEcoded = await DidSiopResponse.generateResponseWithVPData(requestJWT.good.withVPToken.payload, signing, user, 30000, vps);        
        let validity = await DidSiopResponse.validateResponse(response.id_token, checkParams);
        expect(validity).toBeTruthy();

        let validResponse = await DidSiopResponse.validateResponseWithVPData(response,checkParams)
        expect(validResponse).toBeTruthy();
    });

    test("b. Invalid vp_token : generation should raise an exception", async () => {
        jest.setTimeout(30000);
        let user = new Identity();
        await user.resolve(userDID)

        let bad_vp: VPData = {
            vp_token : tokenData.bad.singleVP.vp_token,
            _vp_token : tokenData.bad.singleVP.id_token._vp_token
        };

        let response =  DidSiopResponse.generateResponseWithVPData(requestJWT.good.withVPToken.payload, signing, user, 30000, bad_vp);
        await expect(response).rejects.toEqual(ERROR_RESPONSES.vp_token_missing_verifiableCredential.err);
    });
});

describe("004.04 Response Generation/Validation with the id_token using specific Resolver (did:ethr)", function () {
    beforeEach(() => {
        nock('https://uniresolver.io/1.0/identifiers').persist().get('/'+rpDID).reply(200, rpDidDoc).get('/'+userDID).reply(200, userDidDoc);
    });
    test("a. with basic info : generation and validation", async () => {
        jest.setTimeout(30000);
        let user = new Identity();

        
        let ethrResolver = new EthrDidResolver('key');
        await user.resolve(userDID)

        let response = await DidSiopResponse.generateResponse(requestJWT.good.basic.payload, signing, user, 30000);
        let validity = await DidSiopResponse.validateResponse(response, checkParams,[ethrResolver]);
        expect(validity).toBeTruthy();
        
        let resJWT = toJWTObject(response);
        if (resJWT)
            expect(resJWT.payload.aud).toBe(requestJWT.good.basic.payload.redirect_uri);
    });
});