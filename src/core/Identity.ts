import { KEY_FORMATS, KTYS } from './globals';
import { RESOLVER_URL } from './config';
const axios = require('axios').default;
const { toChecksumAddress } = require('ethereum-checksum-address');

export interface DidDocument{
    '@context': string,
    id: string,
    authentication: any[],
    [propName:string]: any,
}

interface DidPublicKeyMethod{
    id: string,
    type: string,
    publicKeyBase58?: string,
    publicKeyBase64?: string,
    publicKeyHex?: string,
    publicKeyPem?: string,
    publicKeyJwk?: string,
    publicKeyPgp?: string,
    ethereumAddress?: string,
    address?: string,
    [propName: string]: any,
}

export interface DidPublicKey{
    id: string,
    kty: KTYS,
    format: KEY_FORMATS,
    keyString: string,
}

export const ERRORS = Object.freeze(
    {
        DOCUMENT_RESOLUTION_ERROR: 'Cannot resolve document for did',
        INVALID_DID_ERROR: 'Invalid did',
        UNSUPPORTED_KEY_TYPE: 'Unsupported key type',
        UNSUPPORTED_KEY_FORMAT: 'Unsupported key format',
        NO_MATCHING_PUBLIC_KEY: 'No public key matching kid',
        UNRESOLVED_DOCUMENT: 'Unresolved document',
        INVALID_DOCUMENT: 'Invalid did document',
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

    getPublicKey(kid: string): DidPublicKey{
        if(!this.isResolved()) throw new Error(ERRORS.UNRESOLVED_DOCUMENT);
        for (let method of this.doc.authentication) {
            if (method.id && method.id === kid) return getPublicKeyFromDifferentTypes(method);

            if (method.publicKey && method.publicKey.includes(kid)) {
                for (let pub of this.doc.publicKey) {
                    if (pub.id === kid) return getPublicKeyFromDifferentTypes(pub);
                }
            }

            if (method && method === kid) {
                for (let pub of this.doc.publicKey) {
                    if (pub.id === kid) return getPublicKeyFromDifferentTypes(pub);
                }
                //Implement other verification methods here
            }
        }
        throw new Error(ERRORS.NO_MATCHING_PUBLIC_KEY);
    }

    getDocument(): DidDocument{
        return this.doc;
    }

    setDocument(doc: DidDocument, did: string){
        if (
            doc['@context'] === 'https://w3id.org/did/v1' &&
            doc.id == did &&
            doc.authentication &&
            doc.authentication.length > 0
        ) {
            this.doc = doc;
        }
        else {
            throw new Error(ERRORS.INVALID_DOCUMENT);
        }
    }
}

function getKtyFromKeyType(type: string): KTYS {
    switch (type) {
        case 'RsaVerificationKey2018': return KTYS.RSA;
        case 'OpenPgpVerificationKey2019': return KTYS.RSA;
        case 'EcdsaSecp256k1VerificationKey2019': return KTYS.EC;
        case 'Ed25519VerificationKey2018': return KTYS.OKP;
        case 'ED25519SignatureVerification': return KTYS.OKP;
        case 'Curve25519EncryptionPublicKey': return KTYS.OKP;
        case 'Secp256k1SignatureVerificationKey2018': return KTYS.OKP;
        case 'Secp256k1VerificationKey2018': return KTYS.EC;
        default: throw new Error(ERRORS.UNSUPPORTED_KEY_TYPE)
    }
}

function getPublicKeyFromDifferentTypes(key: DidPublicKeyMethod): DidPublicKey {
    if (!key) throw new Error(ERRORS.UNSUPPORTED_KEY_TYPE);
    if (key.publicKeyBase64) {
        return {
            id: key.id,
            kty: getKtyFromKeyType(key.type),
            format: KEY_FORMATS.BASE64,
            keyString: key.publicKeyBase64,
        }
    }
    else if (key.publicKeyBase58) {
        return {
            id: key.id,
            kty: getKtyFromKeyType(key.type),
            format: KEY_FORMATS.BASE58,
            keyString: key.publicKeyBase58,
        }
    }
    else if (key.publicKeyHex) {
        return {
            id: key.id,
            kty: getKtyFromKeyType(key.type),
            format: KEY_FORMATS.HEX,
            keyString: key.publicKeyHex,
        }
    }
    else if (key.publicKeyPem) {
        let format = key.publicKeyPem.indexOf('-----BEGIN RSA PUBLIC KEY-----') > -1 ? KEY_FORMATS.PKCS1_PEM : KEY_FORMATS.PKCS8_PEM;
        return {
            id: key.id,
            kty: getKtyFromKeyType(key.type),
            format: format,
            keyString: key.publicKeyPem,
        }
    }
    else if (key.publicKeyJwk) {
        return {
            id: key.id,
            kty: getKtyFromKeyType(key.type),
            format: KEY_FORMATS.JWK,
            keyString: JSON.stringify(key.publicKeyJwk),
        }
    }
    else if (key.publicKeyPgp) {
        let format = key.publicKeyPgp.indexOf('-----BEGIN RSA PUBLIC KEY-----') > -1 ? KEY_FORMATS.PKCS1_PEM : KEY_FORMATS.PKCS8_PEM;
        return {
            id: key.id,
            kty: getKtyFromKeyType(key.type),
            format: format,
            keyString: key.publicKeyPgp,
        }
    }
    else if (key.ethereumAddress) {
        return {
            id: key.id,
            kty: getKtyFromKeyType(key.type),
            format: KEY_FORMATS.ETHEREUM_ADDRESS,
            keyString: toChecksumAddress(key.ethereumAddress),
        }
    }
    else if (key.address) {
        return {
            id: key.id,
            kty: getKtyFromKeyType(key.type),
            format: KEY_FORMATS.ADDRESS,
            keyString: key.address,
        }
    }
    else throw new Error(ERRORS.UNSUPPORTED_KEY_FORMAT);
}