import { Identity, ERRORS } from './../src/Identity';
import nock from 'nock';

const testDID = 'did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83';
const invalidDID = 'did:eth:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83';
const testResolutionResult = {
    didDocument: {
        '@context': "https://w3id.org/did/v1",
        id: "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83",
        authentication: [
            {
                type: "Secp256k1SignatureAuthentication2018",
                publicKey: [
                    "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83#owner"
                ]
            }
        ],
        publicKey: [
            {
                id: "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83#owner",
                type: "Secp256k1VerificationKey2018",
                ethereumAddress: "0xb07ead9717b44b6cf439c474362b9b0877cbbf83",
                owner: "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83"
            }
        ]
    },
    resolverMetadata: {
        duration: 1289,
        identifier: "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83",
        driverId: "driver-uport/uni-resolver-driver-did-uport-9",
        didUrl: {
            didUrlString: "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83",
            did: {
                didString: "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83",
                method: "ethr",
                methodSpecificId: "0xB07Ead9717b44B6cF439c474362b9B0877CBBF83",
                parseTree: null,
                parseRuleCount: null
            },
            parameters: null,
            parametersMap: { },
            path: "",
            query: null,
            fragment: null,
            parseTree: null,
            parseRuleCount: null
        }
    },
    methodMetadata: { },
    content: null,
    contentType: null
}

describe("Identity functions", function () {
    beforeAll(() => {
        nock('https://uniresolver.io/1.0/identifiers').get('/'+testDID).reply(200, testResolutionResult).get('/'+invalidDID).reply(404, 'Not found');
    });

    test("Tests constructor", async () => {
        let identity = new Identity();
        expect(identity.isResolved()).toBeFalsy();
    });
    test("Tests resolve(did)", async () => {
        let identity = new Identity();
        let resolvedDID = await identity.resolve(testDID);
        expect(resolvedDID).toEqual(testDID);

        let didPromise = identity.resolve(invalidDID);
        await expect(didPromise).rejects.toEqual(ERRORS.DOCUMENT_RESOLUTION_ERROR);
    });
});
