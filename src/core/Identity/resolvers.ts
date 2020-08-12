import { DidDocument } from "./commons";
import { ERRORS } from "./commons";
import { getResolver } from 'ethr-did-resolver';
import * as base58 from 'bs58';
import multibase from "multibase";
import multicodec from 'multicodec';
import ed2curve from 'ed2curve';
const axios = require('axios').default;

abstract class DidResolver{
    constructor(protected methodName: string){}
    abstract async resolveDidDocumet(did: string): Promise<DidDocument>;
    resolve(did: string): Promise<DidDocument>{
        if(did.split(':')[1] !== this.methodName) throw new Error('Incorrect did method');
        return this.resolve(did);
    }
}

class CombinedDidResolver extends DidResolver{
    private resolvers: any[] = [];

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

    resolve(did: string): Promise<DidDocument>{
        return this.resolveDidDocumet(did);
    }
}

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

class UniversalDidResolver extends DidResolver{
    async resolveDidDocumet(did: string): Promise<DidDocument>{
        let returned = await axios.get('https://dev.uniresolver.io/1.0/identifiers/' + did);
        return returned.data.didDocument;
    }

    resolve(did: string): Promise<DidDocument>{
        return this.resolveDidDocumet(did);
    }
}

export const combinedDidResolver = new CombinedDidResolver('all')
    .addResolver(new EthrDidResolver('eth'))
    .addResolver(new KeyDidResolver('key'))
    .addResolver(new UniversalDidResolver('uniresolver'));
