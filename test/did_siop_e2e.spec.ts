import { ERROR_RESPONSES } from './../src/core/ErrorResponse';
import { JWTObject } from './../src/core/JWT';
import { Provider, ERRORS as ProviderErrors } from './../src/core/Provider';
import { RP, ERRORS as RPErrors } from '../src/core/RP';
import nock from 'nock';

let requestObj: JWTObject = {
    header: {
        "alg": "ES256K-R",
        "typ": "JWT",
        "kid": "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83#owner"
    },
    payload:{
        "iss": "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83",
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

let rpDidDoc = {
    didDocument: {
        "@context": "https://w3id.org/did/v1",
        "id": "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83",
        "authentication": [
        {
            "type": "Secp256k1SignatureAuthentication2018",
            "publicKey": [
            "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83#owner"
            ]
        }
        ],
        "publicKey": [
        {
            "id": "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83#owner",
            "type": "Secp256k1VerificationKey2018",
            "ethereumAddress": "0xb07ead9717b44b6cf439c474362b9b0877cbbf83",
            "owner": "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83"
        }
        ]
    }
}
let rpDID = 'did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83';
let rpRedirectURI = 'https://my.rp.com/cb';
let rpRegistrationMetaData = {
        "jwks_uri": "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
        "id_token_signed_response_alg": ["ES256K", "ES256K-R", "EdDSA", "RS256"]
};
let rpPrivateKey = 'CE438802C1F0B6F12BC6E686F372D7D495BC5AA634134B4A7EA4603CB25F0964';
let rpKid = 'did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83#owner';

let userDidDoc = {
    didDocument: {
        "@context": "https://w3id.org/did/v1",
        "id": "did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf",
        "authentication": [
        {
            "type": "Secp256k1SignatureAuthentication2018",
            "publicKey": [
            "did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf#owner"
            ]
        }
        ],
        "publicKey": [
        {
            "id": "did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf#owner",
            "type": "Secp256k1VerificationKey2018",
            "ethereumAddress": "0x30d1707aa439f215756d67300c95bb38b5646aef",
            "owner": "did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf"
        }
        ]
    }
  }
let userDID = 'did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf';
let userPrivateKeyHex = '3f81cb66c8cbba18fbe25f99d2fb4e19f54a1ee69c335ce756a705726189c9e7';
let userKid = 'did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf#owner';

describe('DID SIOP', function () {
    beforeEach(() => {
        nock('https://uniresolver.io/1.0/identifiers').persist().get('/'+rpDID).reply(200, rpDidDoc).get('/'+userDID).reply(200, userDidDoc);
    });
    test('DID SIOP end to end functions testing - expect truthy', async () => {
        jest.setTimeout(10000);

        let rp = await RP.getRP(rpRedirectURI, rpDID, rpRegistrationMetaData);
        rp.addSigningParams(rpPrivateKey, rpKid);

        let provider = new Provider();
        await provider.setUser(userDID);
        provider.addSigningParams(userPrivateKeyHex, userKid);

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
    test('DID SIOP end to end functions testing - expect falsy', async () => {
        jest.setTimeout(10000);

        let rp = await RP.getRP(rpRedirectURI, rpDID, rpRegistrationMetaData);
        rp.addSigningParams(rpPrivateKey, rpKid);

        let provider = new Provider();
        await provider.setUser(userDID);
        provider.addSigningParams(userPrivateKeyHex, userKid);

        rp.removeSigningParams('did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83#owner');
        let requestPromise = rp.generateRequest();
        expect(requestPromise).rejects.toEqual(new Error(RPErrors.NO_SIGNING_INFO));

        provider.removeSigningParams('did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf#owner');
        let responsePromise = provider.generateResponse(requestObj.payload);
        expect(responsePromise).rejects.toEqual(new Error(ProviderErrors.NO_SIGNING_INFO));
    });
    test('DID SIOP end to end functions testing - Error Response', async () => {
        jest.setTimeout(10000);

        let rp = await RP.getRP(rpRedirectURI, rpDID, rpRegistrationMetaData);
        rp.addSigningParams(rpPrivateKey, rpKid);

        let provider = new Provider();
        await provider.setUser(userDID);
        provider.addSigningParams(userPrivateKeyHex, userKid);

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