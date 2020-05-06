import { ERROR_RESPONSES } from './../src/ErrorResponse';
import { DidSiopRequest } from './../src/Request';
import { jwts, requests } from './request.spec.resources';
import nock from 'nock';

describe("Request validation/generation", function () {
    beforeEach(() => {
        nock('http://localhost').get('/requestJWT').reply(200, jwts.jwtGoodEncoded).get('/incorrectRequestJWT').reply(404, 'Not found');
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
        let rqst = await DidSiopRequest.generateRequest(requests.components.rp, requests.components.signing, requests.components.options);
        let decoded = await DidSiopRequest.validateRequest(rqst);
        expect(decoded).toHaveProperty('header');
        expect(decoded).toHaveProperty('payload');
    });
});