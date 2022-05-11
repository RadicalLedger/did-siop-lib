import { DidDocument, DidVerificationKey } from './commons';
import { DidVerificationKeyExtractor } from './key-extractors';
/**
 * @classdesc A class to represent a Decentralized Identity.
 * @property {DidDocument} doc - Decentralized Identity Document. Initialized with empty values in the constructor. Assigned later using resolve(did) method.
 * @property {DidVerificationKey[]} KeySet - A list of verification keys listed in the did-doc. Initialied empty in the constructor. Filled later using extractAuthenticationKeys method.
 */
export declare class Identity {
    private doc;
    private keySet;
    /**
     * @constructor
     */
    constructor();
    /**
     *
     * @param {string} did - A Decentralized Identity to resolve
     * @returns A promise which resolves to the id field of the related Decentralized Idenity Document (did-doc)
     * @remarks The combinedResolver is used to resolve did-doc.
     */
    resolve(did: string): Promise<string>;
    /**
     * @returns true/false to indicate whether the Identity has a resolved did-doc or not
     */
    isResolved(): boolean;
    /**
     *
     * @param {DidVerificationKeyExtractor} [extractor] - The extractor to use when extracting keys. If not provided, uniExtractor is used.
     * @returns An array of DidVerificationKey objects
     * @remarks resolve(did) method must be called before calling this method. This method returns the value of keySet property. If keySet is
     * empty then this method will extract cryptographic keys and related information from the 'authentication' field of did-doc and populate keySet property.
     * https://www.w3.org/TR/did-core/#authentication
     * 'authentication' field is an array and contains Verification Methods in following forms
     *  - A full method which has 'id' and 'type' fields
     *  - A string
     *  - An object with 'type' field and references to 'publicKey' field of did-doc as an array.
     */
    extractAuthenticationKeys(extractor?: DidVerificationKeyExtractor): DidVerificationKey[];
    /**
     * @returns {DidDocument} The doc property.
     */
    getDocument(): DidDocument;
    /**
     *
     * @param {DidDocument} doc
     * @param {string} did - DID related to the doc param
     * @remarks Can be used to set the doc property manually without resolving.
     */
    setDocument(doc: DidDocument, did: string): void;
}
export { DidDocument, DidVerificationKey, DidVerificationKeyMethod, ERRORS } from './commons';
export { DidVerificationKeyExtractor, uniExtractor } from './key-extractors';
