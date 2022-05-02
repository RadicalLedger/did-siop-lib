import { ERROR_RESPONSES } from './../src/core/ErrorResponse';
import { JWTObject } from './../src/core/JWT';
import { Provider, ERRORS as ProviderErrors } from './../src/core/Provider';
import { RP, ERRORS as RPErrors } from '../src/core/RP';
import nock from 'nock';
import {DID_TEST_RESOLVER_DATA_NEW as DIDS } from './did_doc.spec.resources'
import { requests } from './request.spec.resources';

let userDidDoc  = DIDS[0].resolverReturn.didDocument;
let userKeyInfo = DIDS[0].keyInfo;

let userDID     = DIDS[0].did;
let userPrivateKeyHex = userKeyInfo.privateKey;
let userKid = userDidDoc.verificationMethod[1].id;

let rpDidDoc = DIDS[1].resolverReturn.didDocument;
let rpDID = DIDS[1].did;
let rpKeyInfo = DIDS[1].keyInfo;
let rpPrivateKey = rpKeyInfo.privateKey;

let rpKid = rpDidDoc.verificationMethod[1].id;;
let rpRedirectURI = 'https://my.rp.com/cb';
let rpRegistrationMetaData = {
        "jwks_uri": "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
        "id_token_signed_response_alg": ["ES256K", "ES256K-R", "EdDSA", "RS256"]
};

let requestObj: JWTObject = {
    header: {
        "alg": "ES256K",
        "typ": "JWT",
        "kid": rpKid
    },
    payload:{
        "iss": rpDID,
        "response_type": "id_token",
        "scope": "openid did_authn",
        "client_id": "https://my.rp.com/cb",
        "registration": {
          "jwks_uri": "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
          "id_token_signed_response_alg": [
            "ES256K",
            "ES256K-R",
            "EdDSA",
            "RS256"
          ]
        }
      }
}

let badRequest = 'openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid did_authn&request=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiIsImtpZCI6ImRpZDpldGhyOjB4QjA3RWFkOTcxN2I0NEI2Y0Y0MzljNDc0MzYyYjlCMDg3N0NCQkY4MyNvd25lciJ9.eyJyZXNwb25zZV90eXBlIjoiaWRfdG9rZW4iLCJjbGllbnRfaWQiOiJodHRwczovL215LnJwLmNvbS9jYiIsInNjb3BlIjoib3BlbmlkIGRpZF9hdXRobiIsInN0YXRlIjoiYWYwaWZqc2xka2oiLCJub25jZSI6Im4tMFM2X1d6QTJNaiIsInJlc3BvbnNlX21vZGUiOiJmb3JtX3Bvc3QiLCJyZWdpc3RyYXRpb24iOnsiandrc191cmkiOiJodHRwczovL3VuaXJlc29sdmVyLmlvLzEuMC9pZGVudGlmaWVycy9kaWQ6ZXhhbXBsZToweGFiO3RyYW5zZm9ybS1rZXlzPWp3a3MiLCJpZF90b2tlbl9zaWduZWRfcmVzcG9uc2VfYWxnIjpbIkVTMjU2SyIsIkVkRFNBIiwiUlMyNTYiXX19.mXh9VLcxzHFt3D1EFRQm0xDfPB7P4YbnZX2u8Lm46mU4TIbBDqx49tyVMeAx2BCRORAN__JXS2U4NpVheAaX2wA';

describe('DID SIOP', function () {
    beforeEach(() => {
        nock('https://uniresolver.io/1.0/identifiers').persist().get('/'+rpDID).reply(200, rpDidDoc).get('/'+userDID).reply(200, userDidDoc);
    });
    test('DID SIOP end to end functions testing - expect truthy', async () => {
        jest.setTimeout(30000);

        let rp = await RP.getRP(rpRedirectURI, rpDID, rpRegistrationMetaData);
        let kid = rp.addSigningParams(rpPrivateKey);
        expect(kid).toEqual(rpKid);

        let provider = new Provider();
        await provider.setUser(userDID);
        kid = provider.addSigningParams(userPrivateKeyHex);
        expect(kid).toEqual(userKid);

        let request =  await rp.generateRequest();
        let requestJWTDecoded = await provider.validateRequest(request);
        expect(requestJWTDecoded).toMatchObject(requestObj);

        let response = await provider.generateResponse(requestJWTDecoded.payload);
        let responseJWTDecoded = await rp.validateResponse(response, {
            redirect_uri: rpRedirectURI,
            isExpirable: true,
        })
        expect(responseJWTDecoded).toHaveProperty('header');
        expect(responseJWTDecoded).toHaveProperty('payload');
    });
    test('DID SIOP e2e functions testing with VPs- expect truthy', async () => {
        jest.setTimeout(30000);

        let rp = await RP.getRP(rpRedirectURI, rpDID, rpRegistrationMetaData);
        let kid = rp.addSigningParams(rpPrivateKey);
        expect(kid).toEqual(rpKid);

        let provider = new Provider();
        await provider.setUser(userDID);
        kid = provider.addSigningParams(userPrivateKeyHex);
        expect(kid).toEqual(userKid);

        let request =  await rp.generateRequest(requests.components.optionsWithClaims);        
        let requestJWTDecoded = await provider.validateRequest(request);
        expect(requestJWTDecoded).toMatchObject(requestObj);

        let response = await provider.generateResponse(requestJWTDecoded.payload);
        let responseJWTDecoded = await rp.validateResponse(response, {
            redirect_uri: rpRedirectURI,
            isExpirable: true,
            nonce: requests.components.optionsWithClaims.nonce,

        })
        expect(responseJWTDecoded).toHaveProperty('header');
        expect(responseJWTDecoded).toHaveProperty('payload');
    });    
    test('DID SIOP end to end functions testing - expect falsy', async () => {
        jest.setTimeout(30000);

        let rp = await RP.getRP(rpRedirectURI, rpDID, rpRegistrationMetaData);
        rp.addSigningParams(rpPrivateKey);

        let provider = new Provider();
        await provider.setUser(userDID);
        provider.addSigningParams(userPrivateKeyHex);

        rp.removeSigningParams(rpKid);
        let requestPromise = rp.generateRequest();
        expect(requestPromise).rejects.toEqual(new Error(RPErrors.NO_SIGNING_INFO));

        provider.removeSigningParams(userKid);
        let responsePromise = provider.generateResponse(requestObj.payload);
        expect(responsePromise).rejects.toEqual(new Error(ProviderErrors.NO_SIGNING_INFO));
    });
    test('DID SIOP end to end functions testing - Error Response', async () => {
        jest.setTimeout(30000);

        let rp = await RP.getRP(rpRedirectURI, rpDID, rpRegistrationMetaData);
        rp.addSigningParams(rpPrivateKey);

        let provider = new Provider();
        await provider.setUser(userDID);
        provider.addSigningParams(userPrivateKeyHex);

        let requestValidationError = new Error('Unknown error');
        try{
            await provider.validateRequest(badRequest);
        }
        catch(err){
            requestValidationError = err;
        }
        let errorResponse = provider.generateErrorResponse(requestValidationError.message);
        let errorResponseDecoded = await rp.validateResponse(errorResponse);
        expect(errorResponseDecoded).toEqual(ERROR_RESPONSES.invalid_request_object.response);
    })
})