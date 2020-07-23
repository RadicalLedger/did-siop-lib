import { KEY_FORMATS, KTYS, ALGORITHMS } from './globals';
import { RESOLVER_URL } from './config';
import { getKeyType, getAlgorithm } from './Utils';
const axios = require('axios').default;
const { toChecksumAddress } = require('ethereum-checksum-address');

export interface DidDocument{
    '@context': string;
    id: string;
    authentication: any[];
    [propName:string]: any;
}

interface DidVerificationKeyMethod{
    id: string;
    type: string;
    publicKeyBase58?: string;
    publicKeyBase64?: string;
    publicKeyHex?: string;
    publicKeyPem?: string;
    publicKeyJwk?: any;
    publicKeyGpg?: string;
    ethereumAddress?: string;
    address?: string;
    [propName: string]: any;
}

export interface DidVerificationKey{
    id: string;
    kty: KTYS;
    alg: ALGORITHMS,
    format: KEY_FORMATS;
    publicKey: any;
    privateKey?: boolean
}

export const ERRORS = Object.freeze(
    {
        DOCUMENT_RESOLUTION_ERROR: 'Cannot resolve document for did',
        INVALID_DID_ERROR: 'Invalid did',
        UNSUPPORTED_KEY_TYPE: 'Unsupported key type',
        UNSUPPORTED_KEY_FORMAT: 'Unsupported key format',
        NO_MATCHING_PUBLIC_KEY: 'No public key matching kid',
        UNSUPPORTED_PUBLIC_KEY_METHOD: 'Unsupported public key method',
        UNRESOLVED_DOCUMENT: 'Unresolved document',
        INVALID_DOCUMENT: 'Invalid did document',
    }
);

export class Identity{
    private doc: DidDocument;
    private keySet: DidVerificationKey[];

    constructor(){
        this.doc = {
            '@context': '',
            id: '',
            authentication: [],
        };
        this.keySet = [];
    }

    async resolve(did: string): Promise<string>{
        let result;
        try{
            result = await axios.get(RESOLVER_URL + did);
        }
        catch(err){
            throw new Error(ERRORS.DOCUMENT_RESOLUTION_ERROR);
        }

        if(
            result &&
            result.data &&
            result.data.didDocument &&
            //result.data.didDocument['@context'] === 'https://w3id.org/did/v1' &&
            result.data.didDocument.id == did &&
            result.data.didDocument.authentication &&
            result.data.didDocument.authentication.length > 0
        ){
            this.doc = result.data.didDocument;
            this.keySet = [];
            return this.doc.id;
        }
        throw new Error(ERRORS.INVALID_DID_ERROR);
    }

    isResolved(){
        return this.doc.id !== '';
    }

    extractAuthenticationKeys(extractor?: DidVerificationKeyExtractor): DidVerificationKey[]{
        if(!extractor) extractor = uniExtractor;
        if(!this.isResolved()) throw new Error(ERRORS.UNRESOLVED_DOCUMENT);
        for (let method of this.doc.authentication) {
            if (method.id && method.type) {
                try{
                    this.keySet.push(extractor.extract(method));
                }
                catch(err){
                    continue;
                }
            }

            if (method.publicKey) {
                for (let key of method.publicKey) {
                    for(let pub of this.doc.publicKey){
                        if (pub.id === key || pub.id === this.doc.id + key){
                            try{
                                this.keySet.push(extractor.extract(pub));
                            }
                            catch(err){
                                continue;
                            }
                        }
                    }
                }
            }

            if (typeof method === 'string') {
                for (let pub of this.doc.publicKey) {
                    if (pub.id === method){
                        try{
                            this.keySet.push(extractor.extract(pub));
                        }
                        catch(err){
                            continue;
                        }
                    }
                }
                //Implement other verification methods here
            }
        }
        return this.keySet;
    }

    getDocument(): DidDocument{
        return this.doc;
    }

    setDocument(doc: DidDocument, did: string){
        if (
            //doc['@context'] === 'https://w3id.org/did/v1' &&
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

export abstract class DidVerificationKeyExtractor{
    protected names: string[];
    protected next: DidVerificationKeyExtractor | EmptyDidVerificationKeyExtractor;

    constructor(names: string | string[], next?: DidVerificationKeyExtractor){
        this.names = [];
        if(typeof names === 'string'){
            this.names.push(names.toUpperCase());
        }
        else{
            for(let name of names){
                this.names.push(name.toUpperCase())
            }
        }

        if(next){
            this.next = next;
        }
        else{
            this.next = new EmptyDidVerificationKeyExtractor();
        }
    }

    abstract extract(method: DidVerificationKeyMethod): DidVerificationKey;
}

class EmptyDidVerificationKeyExtractor{
    extract(method: DidVerificationKeyMethod): DidVerificationKey{
        if(method){}
        throw new Error(ERRORS.UNSUPPORTED_PUBLIC_KEY_METHOD);
    };
}

class JwsVerificationKey2020Extractor extends DidVerificationKeyExtractor{
    extract(method: DidVerificationKeyMethod): DidVerificationKey {
        if (!method || !method.id || !method.type) throw new Error(ERRORS.NO_MATCHING_PUBLIC_KEY);

        if(this.names.includes(method.type.toUpperCase())){
            if(method.publicKeyJwk){
                return {
                    id: method.id,
                    kty: getKeyType(method.publicKeyJwk.kty),
                    alg: getAlgorithm(method.publicKeyJwk.alg),
                    format: KEY_FORMATS.JWK,
                    publicKey: method.publicKeyJwk
                }
            }
            else{
                throw new Error(ERRORS.UNSUPPORTED_PUBLIC_KEY_METHOD);
            }
        }
        else{
            return this.next.extract(method);
        }
    }
    
}

class Ed25519VerificationKeyExtractor extends DidVerificationKeyExtractor{
    extract(method: DidVerificationKeyMethod): DidVerificationKey {
        if (!method || !method.id || !method.type) throw new Error(ERRORS.NO_MATCHING_PUBLIC_KEY);

        if(this.names.includes(method.type.toUpperCase())){
            let extracted: DidVerificationKey = {
                id: method.id,
                kty: KTYS.OKP,
                alg: ALGORITHMS.EdDSA,
                format: KEY_FORMATS.HEX,
                publicKey: ''
            }
            return getVerificationKeyFromDifferentFormats(method, extracted);
        }
        else{
            return this.next.extract(method);
        }
    }
    
}

class GpgVerificationKey2020Extractor extends DidVerificationKeyExtractor{
    extract(method: DidVerificationKeyMethod): DidVerificationKey {
        if (!method || !method.id || !method.type) throw new Error(ERRORS.NO_MATCHING_PUBLIC_KEY);

        if(this.names.includes(method.type.toUpperCase())){
            if(method.publicKeyGpg){
                return {
                    id: method.id,
                    kty: KTYS.RSA,
                    alg: ALGORITHMS.RS256,
                    format: KEY_FORMATS.PKCS8_PEM,
                    publicKey: method.publicKeyGpg
                }
            }
            else{
                throw new Error(ERRORS.UNSUPPORTED_PUBLIC_KEY_METHOD);
            }
        }
        else{
            return this.next.extract(method);
        }
    }
}

class RsaVerificationKeyExtractor extends DidVerificationKeyExtractor{
    extract(method: DidVerificationKeyMethod): DidVerificationKey {
        if (!method || !method.id || !method.type) throw new Error(ERRORS.NO_MATCHING_PUBLIC_KEY);

        if(this.names.includes(method.type.toUpperCase())){
            let extracted: DidVerificationKey = {
                id: method.id,
                kty: KTYS.RSA,
                alg: ALGORITHMS.RS256,
                format: KEY_FORMATS.HEX,
                publicKey: ''
            }
            return getVerificationKeyFromDifferentFormats(method, extracted);
        }
        else{
            return this.next.extract(method);
        }
    }
}

class EcdsaSecp256k1VerificationKeyExtractor extends DidVerificationKeyExtractor{
    extract(method: DidVerificationKeyMethod): DidVerificationKey {
        if (!method || !method.id || !method.type) throw new Error(ERRORS.NO_MATCHING_PUBLIC_KEY);

        if(this.names.includes(method.type.toUpperCase())){
            let extracted: DidVerificationKey = {
                id: method.id,
                kty: KTYS.EC,
                alg: ALGORITHMS.ES256K,
                format: KEY_FORMATS.HEX,
                publicKey: ''
            }
            return getVerificationKeyFromDifferentFormats(method, extracted);
        }
        else{
            return this.next.extract(method);
        }
    }
}

class EcdsaSecp256r1VerificationKey2019Extractor extends DidVerificationKeyExtractor{
    extract(method: DidVerificationKeyMethod): DidVerificationKey {
        if (!method || !method.id || !method.type) throw new Error(ERRORS.NO_MATCHING_PUBLIC_KEY);

        if(this.names.includes(method.type.toUpperCase())){
            let extracted: DidVerificationKey = {
                id: method.id,
                kty: KTYS.EC,
                alg: ALGORITHMS.ES256,
                format: KEY_FORMATS.HEX,
                publicKey: ''
            }
            return getVerificationKeyFromDifferentFormats(method, extracted);
        }
        else{
            return this.next.extract(method);
        }
    }
}

class EcdsaSecp256k1RecoveryMethod2020Extractor extends DidVerificationKeyExtractor{
    extract(method: DidVerificationKeyMethod): DidVerificationKey {
        if (!method || !method.id || !method.type) throw new Error(ERRORS.NO_MATCHING_PUBLIC_KEY);

        if(this.names.includes(method.type.toUpperCase()) || method.ethereumAddress){
            let extracted: DidVerificationKey = {
                id: method.id,
                kty: KTYS.EC,
                alg: ALGORITHMS["ES256K-R"],
                format: KEY_FORMATS.HEX,
                publicKey: ''
            }
            return getVerificationKeyFromDifferentFormats(method, extracted);
        }
        else{
            return this.next.extract(method);
        }
    }
}

class UniversalDidPublicKeyExtractor extends DidVerificationKeyExtractor{
    extract(method: DidVerificationKeyMethod): DidVerificationKey {
        return this.next.extract(method);
    }
}

// SchnorrSecp256k1VerificationKey2019
// X25519KeyAgreementKey2019

function getVerificationKeyFromDifferentFormats(method: DidVerificationKeyMethod, holder: DidVerificationKey){
    if(!method || !holder) throw new Error(ERRORS.UNSUPPORTED_KEY_FORMAT);

    if(method.publicKeyJwk){
        holder.format = KEY_FORMATS.JWK
        holder.publicKey = method.publicKeyJwk
    }
    else if(method.publicKeyHex){
        holder.format = KEY_FORMATS.HEX;
        holder.publicKey = method.publicKeyHex;
    }
    else if(method.publicKeyBase58){
        holder.format = KEY_FORMATS.BASE58;
        holder.publicKey = method.publicKeyBase58;
    }
    else if(method.publicKeyBase64){
        holder.format = KEY_FORMATS.BASE64;
        holder.publicKey = method.publicKeyBase64;
    }
    else if(method.publicKeyPem){
        holder.format = KEY_FORMATS.PKCS8_PEM;
        holder.publicKey = method.publicKeyPem;
    }
    else if(method.publicKeyPgp){
        holder.format = KEY_FORMATS.PKCS8_PEM;
        holder.publicKey = method.publicKeyGpg;
    }
    else if(method.ethereumAddress){
        holder.format = KEY_FORMATS.ETHEREUM_ADDRESS;
        holder.publicKey = toChecksumAddress(method.ethereumAddress);
    }
    else if(method.address){
        holder.format = KEY_FORMATS.ADDRESS;
        holder.publicKey = method.address;
    }
    else{
        throw new Error(ERRORS.UNSUPPORTED_KEY_FORMAT);
    }
    
    if(holder.format && holder.publicKey){
        return holder;
    }
    else{
        throw new Error(ERRORS.UNSUPPORTED_KEY_FORMAT);
    }
}

const jwsVerificationKey2020Extractor = new JwsVerificationKey2020Extractor('JwsVerificationKey2020');
const ed25519VerificationKeyExtractor = new Ed25519VerificationKeyExtractor(['Ed25519VerificationKey2018', 'ED25519SignatureVerification'], jwsVerificationKey2020Extractor);
const gpgVerificationKey2020Extractor = new GpgVerificationKey2020Extractor('GpgVerificationKey2020', ed25519VerificationKeyExtractor);
const rsaVerificationKeyExtractor = new RsaVerificationKeyExtractor('RsaVerificationKey2018', gpgVerificationKey2020Extractor);
const ecdsaSecp256k1VerificationKeyExtractor = new EcdsaSecp256k1VerificationKeyExtractor(['EcdsaSecp256k1VerificationKey2019', 'Secp256k1VerificationKey2018', 'Secp256k1'], rsaVerificationKeyExtractor);
const ecdsaSecp256r1VerificationKey2019Extractor = new EcdsaSecp256r1VerificationKey2019Extractor('EcdsaSecp256r1VerificationKey2019', ecdsaSecp256k1VerificationKeyExtractor);
const ecdsaSecp256k1RecoveryMethod2020Extractor = new EcdsaSecp256k1RecoveryMethod2020Extractor('EcdsaSecp256k1RecoveryMethod2020', ecdsaSecp256r1VerificationKey2019Extractor);
export const uniExtractor = new UniversalDidPublicKeyExtractor([], ecdsaSecp256k1RecoveryMethod2020Extractor);