import { ERROR_RESPONSES } from '../src/core/ErrorResponse';
import { DidSiopRequest } from '../src/core/Request';
import { jwts, requests, claims } from './request.spec.resources';
import { SIOP_METADATA_SUPPORTED,SiopMetadataSupported } from '../src/core/globals';
import nock from 'nock';
import {DID_TEST_RESOLVER_DATA_NEW as DIDS } from './did_doc.spec.resources'

let userDidDoc  = DIDS[0].resolverReturn.didDocument;
let userDID     = DIDS[0].did;

let rpDidDoc    = DIDS[1].resolverReturn.didDocument;
let rpDID       = DIDS[1].did;

describe("Modify request object", function () {
    test('Include claims - expect truthy', async () => {
        jest.setTimeout(17000);
        let returnedJWT = await DidSiopRequest.validateRequest(requests.good.requestGoodWithClaims,SIOP_METADATA_SUPPORTED);        
        expect(returnedJWT.payload.claims).toEqual(claims.good);
    });
});

describe("Request validation/generation", function () {
    beforeEach(() => {
        nock('http://localhost').get('/requestJWT').reply(200, jwts.jwtGoodEncoded).get('/incorrectRequestJWT').reply(404, 'Not found');
        nock('https://uniresolver.io/1.0/identifiers').persist().get('/'+rpDID).reply(200, rpDidDoc).get('/'+userDID).reply(200, userDidDoc);
    });

    test('Request validation - expect truthy', async () => {
        jest.setTimeout(17000);
        let returnedJWT = await DidSiopRequest.validateRequest(requests.good.requestGoodEmbeddedJWT,SIOP_METADATA_SUPPORTED);
        expect(returnedJWT).toEqual(jwts.jwtGoodDecoded);

        returnedJWT = await DidSiopRequest.validateRequest(requests.good.requestGoodUriJWT,SIOP_METADATA_SUPPORTED);
        expect(returnedJWT).toEqual(jwts.jwtGoodDecoded);
    });

    test('Request validation with invalid OP Metadata - expect falsy', async () => {
        jest.setTimeout(17000);
        let temp_md:SiopMetadataSupported = {...SIOP_METADATA_SUPPORTED}
        temp_md.scopes = [];
        let validityPromise =  DidSiopRequest.validateRequest(requests.good.requestGoodEmbeddedJWT,temp_md);
        await expect(validityPromise).rejects.toEqual(ERROR_RESPONSES.invalid_scope.err);

        temp_md = {...SIOP_METADATA_SUPPORTED}
        temp_md.response_types = [];
        validityPromise =  DidSiopRequest.validateRequest(requests.good.requestGoodEmbeddedJWT,temp_md);
        await expect(validityPromise).rejects.toEqual(ERROR_RESPONSES.unsupported_response_type.err);        

    });


    test('Request validation - expect falsy', async () => {
        jest.setTimeout(17000);
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
});
describe("Request validation/generation", function () {
    test("Generate request - expect truthy", async () => {
        jest.setTimeout(17000);
        let rqst = await DidSiopRequest.generateRequest(requests.components.rp, requests.components.signingInfo, requests.components.options);
        let decoded = await DidSiopRequest.validateRequest(rqst);
        expect(decoded).toHaveProperty('header');
        expect(decoded).toHaveProperty('payload');
    });
    test("Generate request with vp_token and validate - expect truthy", async () => {
        jest.setTimeout(17000);
        let rqst = await DidSiopRequest.generateRequest(requests.components.rp, requests.components.signingInfo, requests.components.optionsWithClaims);
        let decoded = await DidSiopRequest.validateRequest(rqst);
        expect(decoded.payload.claims).toHaveProperty('vp_token');
    });
    test("Generate request with claim but no vp_token - expect reject", async () => {
        jest.setTimeout(17000);
        let validityPromise = DidSiopRequest.validateRequest(requests.bad.requestBadJWTClaimsNoVPToken);
        await expect(validityPromise).rejects.toEqual(ERROR_RESPONSES.vp_token_missing_presentation_definition.err);
    });
});