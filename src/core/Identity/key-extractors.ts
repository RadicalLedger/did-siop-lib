import { DidVerificationKeyMethod, DidVerificationKey, ERRORS } from "./commons";
import { KEY_FORMATS, KTYS, ALGORITHMS } from "../globals";
import { getKeyType, getAlgorithm } from "../Utils";
const { toChecksumAddress } = require('ethereum-checksum-address');

/**
 * @classdesc Abstract class which defines the interface for classes used to extract key
 * information from Verification Methods listed in DID Documents. https://www.w3.org/TR/did-spec-registries/#verification-method-types.
 * Cryptographic Key information used to verify an identity is determined by the Verification Method.
 * In order to extract key info from a specific Verification Method, there must be a subclass extending this class which relates to that
 * Verification Method.
 * @property {string[]} names - A list of names used to refer to a specific Verification Method. Some verification methods have several names.
 * @property {DidVerificationKeyExtractor | EmptyDidVerificationKeyExtractor} next - If this DidVerificationKeyExtractor cannot extract information,
 * it is delegated to another one referenced by next.
 * @remarks This implements Chain-of-responsibility pattern and several extractors can be chained together using next property. This is helpful in
 * situations where the type of Verification Method is not known.
 */
export abstract class DidVerificationKeyExtractor{
    protected names: string[];
    protected next: DidVerificationKeyExtractor | EmptyDidVerificationKeyExtractor;

    /**
     * @constructor
     * @param {string | string[]} names - Name(s) of the Verification Method 
     * @param {DidVerificationKeyExtractor} next - Next extractor. If not provided, EmptyDidVerificationKeyExtractor will be used.
     */
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

    /**
     * 
     * @param {DidVerificationKeyMethod} method Verification Method from which the key information is needed to be extracted.
     * @returns A DidVerificationKey object
     * @remarks Any extending subclass must implement this abstract method. This method contains the process to extract information.
     */
    abstract extract(method: DidVerificationKeyMethod): DidVerificationKey;
}

/**
 * @classdesc A separate extractor class whose extract() method simply returns an error. Used in case reference to next is not provided.
 * Can be used to mark the end of the extractors chain.
 */
class EmptyDidVerificationKeyExtractor{
    extract(method: DidVerificationKeyMethod): DidVerificationKey{
        if(method){}
        throw new Error(ERRORS.UNSUPPORTED_PUBLIC_KEY_METHOD);
    };
}

/**
 * @classdesc Verification Key Extractor class for https://www.w3.org/TR/did-spec-registries/#jwsverificationkey2020
 * @extends {DidVerificationKeyExtractor}
 */
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

/**
 * @classdesc Verification Key Extractor class for https://www.w3.org/TR/did-spec-registries/#ed25519verificationkey2018
 * @extends {DidVerificationKeyExtractor}
 */
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

/**
 * @classdesc Verification Key Extractor class for https://www.w3.org/TR/did-spec-registries/#gpgverificationkey2020
 * @extends {DidVerificationKeyExtractor}
 */
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

/**
 * @classdesc Verification Key Extractor class for https://www.w3.org/TR/did-spec-registries/#rsaverificationkey2018
 * @extends {DidVerificationKeyExtractor}
 */
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

/**
 * @classdesc Verification Key Extractor class for https://www.w3.org/TR/did-spec-registries/#ecdsasecp256k1verificationkey2019
 * @extends {DidVerificationKeyExtractor}
 */
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

/**
 * @classdesc Verification Key Extractor class for EcdsaSecp256r1VerificationKey2019. Related algorithm is ES256. Not mentioned in the spec.
 * @extends {DidVerificationKeyExtractor}
 */
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

/**
 * @classdesc Verification Key Extractor class for https://www.w3.org/TR/did-spec-registries/#ecdsasecp256k1recoverymethod2020
 * @extends {DidVerificationKeyExtractor}
 */
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

/**
 * @classdesc This class is not based on specific Verification Method but simply calls the next. Can be used as the first one in the chain.
 * @extends {DidVerificationKeyExtractor}
 */
class UniversalDidPublicKeyExtractor extends DidVerificationKeyExtractor{
    extract(method: DidVerificationKeyMethod): DidVerificationKey {
        return this.next.extract(method);
    }
}

/**
 * 
 * @param {DidVerificationKeyMethod} method 
 * @param {DidVerificationKey} holder 
 * @returns holder
 * @remarks Cryptographic keys can come in many different formats. This method is used to select the specific key format from a verification method and
 * retreive the key. holder instance holds other information extracted from the Verification Method and this method fills 'format' and 'publicKey' fields. 
 */
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

/**
 * @exports UniversalDidPublicKeyExtractor An instance of UniversalDidPublicKeyExtractor which combines all the other key extractors and act as the head of the chain.
 */
export const uniExtractor = new UniversalDidPublicKeyExtractor([], ecdsaSecp256k1RecoveryMethod2020Extractor);