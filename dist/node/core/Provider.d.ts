import { KEY_FORMATS, ALGORITHMS } from './globals';
import { JWTObject } from './JWT';
import { DidDocument } from './Identity';
export declare const ERRORS: Readonly<{
    NO_SIGNING_INFO: string;
    UNRESOLVED_IDENTITY: string;
    NO_PUBLIC_KEY: string;
}>;
/**
 * @classdesc This class provides the functionality of a DID based Self Issued OpenID Connect Provider
 * @property {Identity} identity  - Used to store Decentralized Identity information of the Provider (end user)
 * @property {SigningInfo[]} signing_info_set - Used to store a list of cryptographic information used to sign id_tokens
 */
export declare class Provider {
    private identity;
    private signing_info_set;
    /**
     * @param {string} did - The DID of the provider (end user)
     * @param {DidDocument} [doc] - DID Document of the provider (end user).
     * @remarks This method is used to set the decentralized identity for the provider (end user).
     * doc parameter is optional and if provided it will be used to directly set the identity.
     * Otherwise the DID Document will be resolved over a related network.
     */
    setUser(did: string, doc?: DidDocument): Promise<void>;
    /**
     * @param {string} key - Private part of any cryptographic key listed in the 'authentication' field of the user's DID Document
     * @param {string} [kid] - kid value of the key. Optional and not used
     * @param {KEY_FORMATS| string} [format] - Format in which the private key is supplied. Optional and not used
     * @param {ALGORITHMS} [algorithm] - Algorithm to use the key with. Optional and not used
     * @returns {string} - kid of the added key
     * @remarks This method is used to add signing information to 'signing_info_set'.
     * All optional parameters are not used and only there to make the library backward compatible.
     * Instead of using those optional parameters, given key is iteratively tried with
     * every public key listed in the 'authentication' field of RP's DID Document and every key format
     * until a compatible combination of those information which can be used for the signing process is found.
     */
    addSigningParams(key: string, kid?: string, format?: KEY_FORMATS | string, algorithm?: ALGORITHMS | string): string;
    /**
     * @param {string} kid - kid value of the SigningInfo which needs to be removed from the list
     * @remarks This method is used to remove a certain SigningInfo (key) which has the given kid value from the list.
     */
    removeSigningParams(kid: string): void;
    /**
     * @param {string} request - A DID SIOP request
     * @returns {Promise<JWT.JWTObject>} - A Promise which resolves to a decoded request JWT
     * @remarks This method is used to validate requests coming from Relying Parties.
     */
    validateRequest(request: string): Promise<JWTObject>;
    /**
     * @param {any} requestPayload - Payload of the request JWT for which a response needs to be generated
     * @param {number} expiresIn - Number of miliseconds under which the generated response is valid. Relying Parties can
     * either consider this value or ignore it
     * @returns {Promise<string>} - A Promise which resolves to an encoded DID SIOP response JWT
     * @remarks This method is used to generate a response to a given DID SIOP request.
     */
    generateResponse(requestPayload: any, expiresIn?: number): Promise<string>;
    /**
     * @param {string} errorMessage - Message of a specific SIOPErrorResponse
     * @returns {string} - Encoded SIOPErrorResponse object
     * @remarks This method is used to generate error responses.
     */
    generateErrorResponse(errorMessage: string): string;
}
