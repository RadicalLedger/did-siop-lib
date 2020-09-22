import { DidDocument } from "./commons";
import { ERRORS } from "./commons";
import { getResolver } from 'ethr-did-resolver';
import * as base58 from 'bs58';
import multibase from "multibase";
import multicodec from 'multicodec';
import ed2curve from 'ed2curve';
const axios = require('axios').default;

/**
 * @classdesc An abstract class which defines the interface for Resolver classes. 
 * Resolvers are used to resolve the Decentralized Identity Document for a given DID.
 * Any extending child class must implement resolveDidDocumet(did) method.
 * @property {string} methodName - Name of the specific DID Method. Used as a check to resolve only DIDs related to this DID Method. 
 */
abstract class DidResolver{
    /**
     * @constructor
     * @param {string} methodName - Name of the specific DID Method.  
     */
    constructor(protected methodName: string){}

    /**
     * 
     * @param {string} did - DID to resolve the DID Document for.
     * @returns A promise which resolves to a {DidDocument}
     * @remarks Any inheriting child class must implement this abstract method. Relates to the Read operation of the DID Method.
     */
    abstract async resolveDidDocumet(did: string): Promise<DidDocument>;

    /**
     * 
     * @param {string} did - DID to resolve the DID Document for.
     * @returns A promise which resolves to a {DidDocument}
     * @remarks A wrapper method which make use of methodName property and resolveDidDocumet(did) method
     * to resolve documents for related DIDs only. Throws an error for DIDs of other DID Methods.
     */
    resolve(did: string): Promise<DidDocument>{
        if(did.split(':')[1] !== this.methodName) throw new Error('Incorrect did method');
        return this.resolve(did);
    }
}

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
    async resolveDidDocumet(did: string): Promise<DidDocument> {
        const providerConfig = { rpcUrl: 'https://ropsten.infura.io/v3/e0a6ac9a2c4a4722970325c36b728415'};
        let resolve = getResolver(providerConfig).ethr;
        return await resolve(did, {
            did,
            method: 'ethr',
            id: did.split(':')[2],
            didUrl: did
        });
    }
}

/**
 * @classdesc Resolver class for DID-KEY DIDs. These DIDs are for test purposes only.
 * @extends {DidResolver}
 */
class KeyDidResolver extends DidResolver{
    resolveDidDocumet(did: string): Promise<DidDocument> {
        if(!did) {
            throw new TypeError('"did" must be a string.');
        }
        
        const didAuthority = did.split('#')[0];
        const fingerprint = didAuthority.substr('did:key:'.length);
        
        const decodedFingerprint = multibase.decode(fingerprint);
        const unprefixed = multicodec.rmPrefix(decodedFingerprint);
        const publicKey = base58.encode(unprefixed);
        const keyId = did + '#' + fingerprint;

        const keyAgreementKeyBuffer = ed2curve.convertPublicKey(unprefixed);
        if(!keyAgreementKeyBuffer) throw new Error('Cannot derive keyAgreement');
        const keyAgreementKey = base58.encode(keyAgreementKeyBuffer);
        
        const keyAgreementIdBuffer = Buffer.alloc(2 + keyAgreementKeyBuffer.length);
        keyAgreementIdBuffer[0] = 0xec;
        keyAgreementIdBuffer[1] = 0x01;
        keyAgreementIdBuffer.set(keyAgreementKeyBuffer, 2);
        const keyAgreementId = did + '#' + 'z' + base58.encode(keyAgreementIdBuffer);

        const didDoc = {
            '@context': ['https://w3id.org/did/v0.11'],
            id: did,
            publicKey: [{
                id: keyId,
                type: 'Ed25519VerificationKey2018',
                controller: did,
                publicKeyBase58: publicKey
            }],
            authentication: [keyId],
            assertionMethod: [keyId],
            capabilityDelegation: [keyId],
            capabilityInvocation: [keyId],
            keyAgreement: [{
                id: keyAgreementId,
                type: 'X25519KeyAgreementKey2019',
                controller: did,
                publicKeyBase58: keyAgreementKey
            }]
        };
        
        console.log('resolved by did:key\n' + JSON.stringify(didDoc));
        return Promise.resolve(didDoc);
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
    .addResolver(new EthrDidResolver('eth'))
    .addResolver(new KeyDidResolver('key'))
    .addResolver(new UniversalDidResolver('uniresolver'));
