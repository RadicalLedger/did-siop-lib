import { RESOLVER_URL } from './config';
const axios = require('axios').default;
const { toChecksumAddress } = require('ethereum-checksum-address');

export interface DidDocument{
    '@context': string,
    id: string,
    authentication: any[],
    [propName:string]: any,
}

export const ERRORS = Object.freeze(
    {
        DOCUMENT_RESOLUTION_ERROR: 'Cannot resolve document for did',
        INVALID_DID_ERROR: 'Invalid did',
        UNSUPPORTED_KEY_TYPE: 'Unsupported key type',
        NO_MATCHING_PUBLIC_KEY: 'No public key matching kid',
        UNRESOLVED_DOCUMENT: 'Unresolved document',
    }
);

export class Identity{
    private doc: DidDocument;

    constructor(){
        this.doc = {
            '@context': '',
            id: '',
            authentication: [],
        };
    }

    async resolve(did: string){
        try{
            let result = await axios.get(RESOLVER_URL + did);
            if(
                result &&
                result.data &&
                result.data.didDocument &&
                result.data.didDocument['@context'] === 'https://w3id.org/did/v1' &&
                result.data.didDocument.id == did &&
                result.data.didDocument.authentication &&
                result.data.didDocument.authentication.length > 0
            ){
                this.doc = result.data.didDocument;
                return this.doc.id;
            }
            throw new Error(ERRORS.INVALID_DID_ERROR);
        }
        catch(err){
            throw new Error(ERRORS.DOCUMENT_RESOLUTION_ERROR);
        }
    }

    isResolved(){
        return this.doc.id !== '';
    }

    private getPublicKeyFromDifferentTypes(key: any): any {
        if (!key) throw new Error(ERRORS.UNSUPPORTED_KEY_TYPE);
        if (key.publicKeyBase64) return key.publicKeyBase64;
        else if (key.publicKeyBase58) return key.publicKeyBase58;
        else if (key.publicKeyHex) return key.publicKeyHex;
        else if (key.publicKeyPem) return key.publicKeyPem;
        else if (key.publicKeyJwk) return key.publicKeyJwk;
        else if (key.publicKeyPgp) return key.publicKeyPgp;
        else if (key.ethereumAddress) return toChecksumAddress(key.ethereumAddress);
        else if (key.address) return key.address;
        else throw new Error(ERRORS.UNSUPPORTED_KEY_TYPE);
    }

    getPublicKey(kid: string): any{
        if(!this.isResolved()) throw new Error(ERRORS.UNRESOLVED_DOCUMENT);
        for (let method of this.doc.authentication) {
            if (method.id === kid) return this.getPublicKeyFromDifferentTypes(method);

            if (method.publicKey && method.publicKey.includes(kid)) {
                for (let pub of this.doc.publicKey) {
                    if (pub.id === kid) return this.getPublicKeyFromDifferentTypes(pub);
                }
            }

            if (method === kid) {
                for (let pub of this.doc.publicKey) {
                    if (pub.id === kid) return this.getPublicKeyFromDifferentTypes(pub);
                }
                //Implement other verification methods here
            }
        }
        throw new Error(ERRORS.NO_MATCHING_PUBLIC_KEY);
    }

    getDocument(): DidDocument{
        return this.doc;
    }
}