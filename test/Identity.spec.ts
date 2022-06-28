import { Identity} from '../src/core/identity';
import { KeyDidResolver } from '../src/core/identity/resolvers';
import {DID_TEST_RESOLVER_DATA_NEW } from './did-doc.spec.resources'

describe("002. Identity functions", function() {
    jest.setTimeout(17000);
    test("a. Using default resolver", async () => {
        let resolverData = DID_TEST_RESOLVER_DATA_NEW[0]

        let identity = new Identity();

        let resolvedDID = await identity.resolve(resolverData.did);
        expect(resolvedDID).toEqual(resolverData.did);
        expect(identity.isResolved()).toBeTruthy();
    
    });
    test("b. Using soecific resolver (did:key)", async () => {
        let resolverData = DID_TEST_RESOLVER_DATA_NEW[3] // did:key
        let keyResolver = new KeyDidResolver('key');

        let identity = new Identity();
        identity.addResolvers([keyResolver])

        let resolvedDID = await identity.resolve(resolverData.did);
        expect(resolvedDID).toEqual(resolverData.did);
        expect(identity.isResolved()).toBeTruthy();
    
    });

});