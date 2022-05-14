import { DidDocument } from './Identity';
import * as JWT from './JWT';
export interface RPInfo {
    redirect_uri: string;
    did: string;
    registration: any;
    did_doc?: DidDocument;
    request_uri?: string;
}
/**
 * @classdesc This class contains static methods related to DID SIOP request generation and validation
 */
export declare class DidSiopRequest {
    /**
     * @param {string} request - A request which needs to be checked for validity
     * @returns {Promise<JWT.JWTObject>} - A Promise which resolves to the decoded request JWT
     * @remarks This method make use of two functions which first validates the url parameters of the request
     * and then the request JWT contained in 'request' or 'requestURI' parameter
     */
    static validateRequest(request: string): Promise<JWT.JWTObject>;
    /**
     * @param {RPInfo} rp - Information about the Relying Party (the issuer of the request)
     * @param {JWT.SigningInfo} signingInfo - Information used in the request signing process
     * @param {any} options - Optional fields. Directly included in the request JWT.
     * Any optional field if not supported will be ignored
     * @returns {Promise<string>} - A Promise which resolves to the request
     * @remarks This method is used to generate a DID SIOP request using information provided by the Relying Party.
     * Process has two steps. First generates the request with URL params
     * and then creates the signed JWT (unless the 'requestURI' field is specified in RPInfo).
     * JWT is then added to the 'request' param of the request.
     * https://identity.foundation/did-siop/#generate-siop-request
     */
    static generateRequest(rp: RPInfo, signingInfo: JWT.SigningInfo, options: any): Promise<string>;
}
