import { ERROR_RESPONSES } from './../src/core/ErrorResponse';
import { DidSiopRequest } from './../src/core/Request';
import { jwts, requests } from './request.spec.resources';
import nock from 'nock';

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

describe("Request validation/generation", function () {
    beforeEach(() => {
        nock('http://localhost').get('/requestJWT').reply(200, jwts.jwtGoodEncoded).get('/incorrectRequestJWT').reply(404, 'Not found');
        nock('https://uniresolver.io/1.0/identifiers').persist().get('/'+rpDID).reply(200, rpDidDoc).get('/'+userDID).reply(200, userDidDoc);
    });

    test('Request validation - expect truthy', async () => {
        jest.setTimeout(7000);
        let returnedJWT = await DidSiopRequest.validateRequest(requests.good.requestGoodEmbeddedJWT);
        expect(returnedJWT).toEqual(jwts.jwtGoodDecoded);

        returnedJWT = await DidSiopRequest.validateRequest(requests.good.requestGoodUriJWT);
        expect(returnedJWT).toEqual(jwts.jwtGoodDecoded);
    });

    test('Request validation - expect falsy', async () => {
        jest.setTimeout(7000);
        let validityPromise = DidSiopRequest.validateRequest(requests.bad.requestBadProtocol);
        await expect(validityPromise).rejects.toEqual(ERROR_RESPONSES.invalid_request.err);

        validityPromise = DidSiopRequest.validateRequest(requests.bad.requestBadNoSlashes);
        await expect(validityPromise).rejects.toEqual(ERROR_RESPONSES.invalid_request.err);

        validityPromise = DidSiopRequest.validateRequest(requests.bad.requestBadNoResponseType);
        await expect(validityPromise).rejects.toEqual(ERROR_RESPONSES.invalid_request.err);

        validityPromise = DidSiopRequest.validateRequest(requests.bad.requestBadIncorrectResponseType);
        await expect(validityPromise).rejects.toEqual(ERROR_RESPONSES.unsupported_response_type.err);

        validityPromise = DidSiopRequest.validateRequest(requests.bad.requestBadNoClientId);
        await expect(validityPromise).rejects.toEqual(ERROR_RESPONSES.invalid_request.err);

        validityPromise = DidSiopRequest.validateRequest(requests.bad.requestBadNoScope);
        await expect(validityPromise).rejects.toEqual(ERROR_RESPONSES.invalid_scope.err);

        validityPromise = DidSiopRequest.validateRequest(requests.bad.requestBadNoScopeOpenId);
        await expect(validityPromise).rejects.toEqual(ERROR_RESPONSES.invalid_scope.err);

        validityPromise = DidSiopRequest.validateRequest(requests.bad.requestBadNoScopeDidAuthN);
        await expect(validityPromise).rejects.toEqual(ERROR_RESPONSES.invalid_scope.err);

        validityPromise = DidSiopRequest.validateRequest(requests.bad.requestBadNoJWT);
        await expect(validityPromise).rejects.toEqual(ERROR_RESPONSES.invalid_request_object.err);

        validityPromise = DidSiopRequest.validateRequest(requests.bad.requestBadNoJWTUri);
        await expect(validityPromise).rejects.toEqual(ERROR_RESPONSES.invalid_request_uri.err);

        validityPromise = DidSiopRequest.validateRequest(requests.bad.requestBadIncorrectJWTUri);
        await expect(validityPromise).rejects.toEqual(ERROR_RESPONSES.invalid_request_uri.err);

        validityPromise = DidSiopRequest.validateRequest(requests.bad.requestBadJWTNoIss);
        await expect(validityPromise).rejects.toEqual(ERROR_RESPONSES.invalid_request_object.err);

        validityPromise = DidSiopRequest.validateRequest(requests.bad.requestBadJWTNoKid);
        await expect(validityPromise).rejects.toEqual(ERROR_RESPONSES.invalid_request_object.err);

        validityPromise = DidSiopRequest.validateRequest(requests.bad.requestBadJWTNoRegistration);
        await expect(validityPromise).rejects.toEqual(ERROR_RESPONSES.invalid_request_object.err);

        validityPromise = DidSiopRequest.validateRequest(requests.bad.requestBadJWTNoScope);
        await expect(validityPromise).rejects.toEqual(ERROR_RESPONSES.invalid_request_object.err);

        validityPromise = DidSiopRequest.validateRequest(requests.bad.requestBadJWTIncorrectScope);
        await expect(validityPromise).rejects.toEqual(ERROR_RESPONSES.invalid_request_object.err);
    });
    test("Generate request - expect truthy", async () => {
        jest.setTimeout(7000);
        let rqst = await DidSiopRequest.generateRequest(requests.components.rp, requests.components.signingInfo, requests.components.options);
        let decoded = await DidSiopRequest.validateRequest(rqst);
        expect(decoded).toHaveProperty('header');
        expect(decoded).toHaveProperty('payload');
    });
});