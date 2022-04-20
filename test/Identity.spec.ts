import { Identity} from '../src/core/Identity';
// import nock from 'nock';
import {DID_TEST_RESOLVER_DATA_NEW } from './did_doc.spec.resources'

describe("NEW Identity2 functions", function() {
    jest.setTimeout(17000);
    test("0.NEW Tests resolve(did)", async () => {
        let identity;
        let resolverData = DID_TEST_RESOLVER_DATA_NEW[0]
        // nock('https://dev.uniresolver.io/1.0/identifiers/').get('/' + resolverData.did).reply(200, resolverData.resolverReturn).get('/' + invalidDID).reply(404, 'Not found');

        identity = new Identity();
        let resolvedDID = await identity.resolve(resolverData.did);
        expect(resolvedDID).toEqual(resolverData.did);
        expect(identity.isResolved()).toBeTruthy();
    
    });
});
