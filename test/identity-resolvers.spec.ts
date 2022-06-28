import { CombinedDidResolver, EthrDidResolver, KeyDidResolver } from '../src/core/identity/resolvers';
import {DID_TEST_RESOLVER_DATA_NEW } from './did-doc.spec.resources'

describe("001.01 CombinedDidResolver Functionalities with default resolver", function() {
    jest.setTimeout(17000);
    test("a. ability to resolve using default resolver", async () => {
        let combinedDidResolver = new CombinedDidResolver('all')
        let resolverData = DID_TEST_RESOLVER_DATA_NEW[0]; //did:ethr
        let resolvedDID = await combinedDidResolver.resolveDidDocumet(resolverData.did);

        expect(resolvedDID.id).toEqual(resolverData.did);
    });
});

describe("001.02 CombinedDidResolver Functionalities with given Resolver ", function() {
    jest.setTimeout(17000);
    test("a. ability to add EthrDidResolver and resolve a DID", async () => {
        let combinedDidResolver = new CombinedDidResolver('')        
        let resolverData = DID_TEST_RESOLVER_DATA_NEW[0] //did:ethr
        let ethrResolver = new EthrDidResolver('ethr');
        combinedDidResolver.addResolver(ethrResolver);

        expect(combinedDidResolver.getResolvers().length).toEqual(1);
        let resolvedDID = await combinedDidResolver.resolveDidDocumet(resolverData.did)

        expect(resolvedDID.id).toEqual(resolverData.did);        
    });
    test("b. ability to add KeyDidResolver and resolve a DID", async () => {
        let combinedDidResolver = new CombinedDidResolver('')        
        let resolverData = DID_TEST_RESOLVER_DATA_NEW[3] //did:key
        let keyResolver = new KeyDidResolver('key');
        combinedDidResolver.addResolver(keyResolver);

        expect(combinedDidResolver.getResolvers().length).toEqual(1);
        let resolvedDID = await combinedDidResolver.resolveDidDocumet(resolverData.did)

        expect(resolvedDID.id).toEqual(resolverData.did);            
    });
    test("c. ability to add multiple resolvers and resolve a DID", async () => {
        let combinedDidResolver = new CombinedDidResolver('')        
        let resolverDataKey = DID_TEST_RESOLVER_DATA_NEW[3] //did:key
        let resolverDataEthr = DID_TEST_RESOLVER_DATA_NEW[0] //did:ethr        
        let keyResolver = new KeyDidResolver('key');
        let ethrResolver = new EthrDidResolver('ethr');
        combinedDidResolver.addResolver(keyResolver);
        combinedDidResolver.addResolver(ethrResolver);

        expect(combinedDidResolver.getResolvers().length).toEqual(2);
        let resolvedDIDKey = await combinedDidResolver.resolveDidDocumet(resolverDataKey.did)        
        let resolvedDIDEthr = await combinedDidResolver.resolveDidDocumet(resolverDataEthr.did)

        expect(resolvedDIDKey.id).toEqual(resolverDataKey.did);
        expect(resolvedDIDEthr.id).toEqual(resolverDataEthr.did);

    });
});