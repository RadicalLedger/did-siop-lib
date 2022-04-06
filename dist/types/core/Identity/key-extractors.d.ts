import { DidVerificationKeyMethod, DidVerificationKey } from "./commons";
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
export declare abstract class DidVerificationKeyExtractor {
    protected names: string[];
    protected next: DidVerificationKeyExtractor | EmptyDidVerificationKeyExtractor;
    /**
     * @constructor
     * @param {string | string[]} names - Name(s) of the Verification Method
     * @param {DidVerificationKeyExtractor} next - Next extractor. If not provided, EmptyDidVerificationKeyExtractor will be used.
     */
    constructor(names: string | string[], next?: DidVerificationKeyExtractor);
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
declare class EmptyDidVerificationKeyExtractor {
    extract(method: DidVerificationKeyMethod): DidVerificationKey;
}
/**
 * @classdesc This class is not based on specific Verification Method but simply calls the next. Can be used as the first one in the chain.
 * @extends {DidVerificationKeyExtractor}
 */
declare class UniversalDidPublicKeyExtractor extends DidVerificationKeyExtractor {
    extract(method: DidVerificationKeyMethod): DidVerificationKey;
}
/**
 * @exports UniversalDidPublicKeyExtractor An instance of UniversalDidPublicKeyExtractor which combines all the other key extractors and act as the head of the chain.
 */
export declare const uniExtractor: UniversalDidPublicKeyExtractor;
export {};
