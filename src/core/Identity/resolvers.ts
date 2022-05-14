import { DidDocument } from "./commons";
import { DidResolver } from "./did_resolver_base";
import { KeyDidResolver2 } from "./did_resolver_key";

import { ERRORS } from "./commons";
import { Resolver } from 'did-resolver'
import { getResolver } from 'ethr-did-resolver';
import { CRYPTO_SUITES } from "../globals";
const axios = require('axios').default;

/**
 * @classdesc A Resolver class which combines several other Resolvers in chain.
 * A given DID is tried with each Resolver object and if fails, passed to the next one in the chain.
 * @property {any[]} resolvers - An array to contain instances of other classes which implement DidResolver class. 
 * @extends {DidResolver}
 */
class CombinedDidResolver extends DidResolver{
    private resolvers: any[] = [];

    /**
     * 
     * @param {any} resolver - A resolver instance to add to the chain.
     * @returns {CombinedDidResolver} To use in fluent interface pattern.
     * @remarks Adds a given object to the resolvers array.
     */
    addResolver(resolver: any): CombinedDidResolver{
        this.resolvers.push(resolver);
        return this;
    }

    async resolveDidDocumet(did: string): Promise<DidDocument>{
        let doc: DidDocument | undefined;

        for(let resolver of this.resolvers){
            try{
                doc = await resolver.resolve(did);
                if(!doc){
                    continue;
                }
                else{
                    return doc;
                }
            }
            catch(err){
                continue;
            }
        }
        throw new Error(ERRORS.DOCUMENT_RESOLUTION_ERROR);
    }

    /**
     * 
     * @param {string} did - DID to resolve the DID Document for.
     * @returns A promise which resolves to a {DidDocument}
     * @override resolve(did) method of the {DidResolver}
     * @remarks Unlike other resolvers this class can resolve Documents for many DID Methods.
     * Therefore the check in the parent class needs to be overridden.
     */
    resolve(did: string): Promise<DidDocument>{
        return this.resolveDidDocumet(did);
    }
}

/**
 * @classdesc Resolver class for Ethereum DIDs
 * @extends {DidResolver}
 */
 class EthrDidResolver extends DidResolver{
    async resolveDidDocumet(did: string): Promise<DidDocument | undefined> {
        const providerConfig = { name : "rinkeby", rpcUrl: 'https://rinkeby.infura.io/v3/e0a6ac9a2c4a4722970325c36b728415'};
        let ethrDidResolver = getResolver(providerConfig);
        const didResolver = new Resolver(ethrDidResolver)
        try {
            let result:any = await didResolver.resolve(did);
            let didDoc : DidDocument = {...result.didDocument}
            return didDoc;
        }
        catch(e) {
            return undefined;
        }
    }
}


/**
 * @classdesc Resolver class which is based on the endpoint of https://dev.uniresolver.io/.
 * Can be used resolve Documents for any DID Method supported by the service.
 * @extends {DidResolver}
 */
class UniversalDidResolver extends DidResolver{
    async resolveDidDocumet(did: string): Promise<DidDocument>{
        let returned = await axios.get('https://dev.uniresolver.io/1.0/identifiers/' + did);
        return returned.data.didDocument;
    }

    /**
     * 
     * @param {string} did - DID to resolve the DID Document for.
     * @returns A promise which resolves to a {DidDocument}
     * @override resolve(did) method of the {DidResolver}
     * @remarks Unlike other resolvers this class can resolve Documents for many DID Methods.
     * Therefore the check in the parent class needs to be overridden.
     */
    resolve(did: string): Promise<DidDocument>{
        return this.resolveDidDocumet(did);
    }
}

/**
 * @exports CombinedDidResolver An instance of CombinedResolver which includes resolvers for currenlty implemented DID Methods.
 */
export const combinedDidResolver = new CombinedDidResolver('all')
    .addResolver(new EthrDidResolver('ethr'))
    // .addResolver(new KeyDidResolver('key'))
    .addResolver(new KeyDidResolver2('key', CRYPTO_SUITES.Ed25519VerificationKey2018))
    .addResolver(new KeyDidResolver2('key', CRYPTO_SUITES.Ed25519VerificationKey2020))    
    .addResolver(new UniversalDidResolver('uniresolver'));
