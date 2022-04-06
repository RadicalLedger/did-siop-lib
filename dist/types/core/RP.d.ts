import { CheckParams } from './Response';
import { JWTObject } from './JWT';
import { DidDocument } from './Identity';
import { KEY_FORMATS, ALGORITHMS } from './globals';
import { SIOPErrorResponse } from './ErrorResponse';
export declare const ERRORS: Readonly<{
    NO_SIGNING_INFO: string;
    NO_PUBLIC_KEY: string;
}>;
/**
 * @classdesc This class provides the Relying Party functionality of DID based Self Issued OpenID Connect
 * @property {RPInfo} - Used to hold Relying Party information needed in issuing requests (ex:- redirect_uri)
 * @property {Identity} identity  - Used to store Decentralized Identity information of the Relying Party
 * @property {SigningInfo[]} signing_info_set - Used to store a list of cryptographic information used to sign DID SIOP requests
 */
export declare class RP {
    private info;
    private identity;
    private signing_info_set;
    /**
     * @private
     * @constructor
     * @param {string} redirect_uri - Redirect uri of the RP. Response from the Provider is sent to this uri
     * @param {string} did - Decentralized Identity of the Relying Party
     * @param {any} registration - Registration information of the Relying Party
     * https://openid.net/specs/openid-connect-core-1_0.html#RegistrationParameter
     * @param {DidDocument} [did_doc] - DID Document of the RP. Optional
     * @remarks - This is a private constructor used inside static async method getRP
     */
    private constructor();
    /**
     * @param {string} redirect_uri - Redirect uri of the RP. Response from the Provider is sent to this uri
     * @param {string} did - Decentralized Identity of the Relying Party
     * @param {any} registration - Registration information of the Relying Party
     * https://openid.net/specs/openid-connect-core-1_0.html#RegistrationParameter
     * @param {DidDocument} [did_doc] - DID Document of the RP. Optional
     * @returns {Promise<RP>} - A Promise which resolves to an instance of RP class
     * @remarks Creating RP instances involves some async code and cannot be implemented as a constructor.
     * Hence this static method is used in place of the constructor.
     */
    static getRP(redirect_uri: string, did: string, registration: any, did_doc?: DidDocument): Promise<RP>;
    /**
     * @param {string} key - Private part of any cryptographic key listed in the 'authentication' field of RP's DID Document
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
     * @param {any} [options = {}] - Any optional field which should be included in the request JWT. Any field which is not supported
     * at Provider's end will be ignored
     * @returns {Promise<string>} - A Promise which resolves to a DID SIOP request
     * @remarks This method is used to generate a request sent to a DID SIOP Provider.
     */
    generateRequest(options?: any): Promise<string>;
    /**
     * @param {string} request_uri - A uri from which a pre-configured and signed request JWT can be obtained
     * @param {any} [options = {}] - Any optional field which should be included in the request JWT. Any field which is not supported
     * at Provider's end will be ignored
     * @returns {Promise<string>} - A Promise which resolves to a DID SIOP request
     * @remarks This method is used to generate a request which has 'request_uri' in place of the 'request' parameter.
     * https://identity.foundation/did-siop/#generate-siop-request
     */
    generateUriRequest(request_uri: string, options?: any): Promise<string>;
    /**
     * @param {string} response - A DID SIOP response
     * @param {CheckParams} [checkParams = {redirect_uri: this.info.redirect_uri}] - Parameters against which the response needs to be validated
     * @returns {Promise<JWT.JWTObject> | SIOPErrorResponse} - A Promise which resolves either to a decoded response or a SIOPErrorResponse
     * @remarks This method is used to validate responses coming from DID SIOP Providers.
     */
    validateResponse(response: string, checkParams?: CheckParams): Promise<JWTObject | SIOPErrorResponse>;
}
