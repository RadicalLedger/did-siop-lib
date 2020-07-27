import { Identity, ERRORS, uniExtractor } from '../src/core/Identity';
import nock from 'nock';
import { DID_TEST_RESOLVER_DATA, invalidDID } from './did_doc.spec.resources'

describe("Identity functions", function() {

    test("Tests constructor", async () => {
        let identity = new Identity();
        expect(identity.isResolved()).toBeFalsy();
    });

    test("Tests resolve(did)", async () => {
        let identity;
        for(let resolverData of DID_TEST_RESOLVER_DATA){
            nock('https://uniresolver.io/1.0/identifiers').get('/' + resolverData.did).reply(200, resolverData.resolverReturn).get('/' + invalidDID).reply(404, 'Not found');
            identity = new Identity();
            let resolvedDID = await identity.resolve(resolverData.did);
            expect(resolvedDID).toEqual(resolverData.did);
            expect(identity.isResolved()).toBeTruthy();
        }

        identity = new Identity();
        let didPromise = identity.resolve(invalidDID);
        await expect(didPromise).rejects.toEqual(new Error(ERRORS.DOCUMENT_RESOLUTION_ERROR));
    });

    test("Tests extractAuthenticationKeys()", async () => {
        let identity = new Identity();
        expect(() => {
            identity.extractAuthenticationKeys(uniExtractor);
        }).toThrow(new Error(ERRORS.UNRESOLVED_DOCUMENT));

        for(let resolverData of DID_TEST_RESOLVER_DATA){
            nock('https://uniresolver.io/1.0/identifiers').get('/' + resolverData.did).reply(200, resolverData.resolverReturn).get('/' + invalidDID).reply(404, 'Not found');

            identity = new Identity();
            await identity.resolve(resolverData.did);

            let publicKey = identity.extractAuthenticationKeys(uniExtractor).filter(pk => {return pk.id === resolverData.keys[0].id})[0];
            expect(publicKey).toEqual(resolverData.keys[0]);
        }
    });
});
