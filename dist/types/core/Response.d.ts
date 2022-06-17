import * as JWT from './JWT';
import { Identity } from './Identity';
import * as ErrorResponse from './ErrorResponse';
import { VPData, SIOPTokensEcoded, SIOPTokenObjects } from './Claims';
export interface CheckParams {
    redirect_uri: string;
    nonce?: string;
    validBefore?: number;
    isExpirable?: boolean;
}
/**
 * @classdesc This class contains static methods related to DID SIOP response generation and validation
 */
export declare class DidSiopResponse {
    /**
     * @param {any} requestPayload - Payload of the request JWT. Some information from this object is needed in constructing the response
     * @param {JWT.SigningInfo} signingInfo - Key information used to sign the response JWT
     * @param {Identity} didSiopUser - Used to retrieve the information about the provider (user DID) which are included in the response
     * @param {number} [expiresIn = 1000] - Amount of time under which generated id_token (response) is valid. The party which validate the
     * response can either consider this value or ignore it
     * @returns {Promise<string>} - A promise which resolves to a response (id_token) (JWT)
     * @remarks This method first checks if given SigningInfo is compatible with the algorithm required by the RP in
     * 'requestPayload.registration.id_token_signed_response_alg' field.
     * Then it proceeds to extract provider's (user) public key from 'didSiopUser' param using 'kid' field in 'signingInfo' param.
     * Finally it will create the response JWT (id_token) with relevant information, sign it using 'signingInfo' and return it.
     * https://identity.foundation/did-siop/#generate-siop-response
     */
    static generateResponse(requestPayload: any, signingInfo: JWT.SigningInfo, didSiopUser: Identity, expiresIn?: number, vps?: VPData): Promise<string>;
    /**
     * @param {any} requestPayload - Payload of the request JWT. Some information from this object is needed in constructing the response
     * @param {JWT.SigningInfo} signingInfo - Key information used to sign the response JWT
     * @param {Identity} didSiopUser - Used to retrieve the information about the provider (user DID) which are included in the response
     * @param {number} [expiresIn = 1000] - Amount of time under which generated id_token (response) is valid. The party which validate the
     * @param {vps} VPData - This contains the data for vp_token and additional info to send via id_token (_vp_token)
     * @returns {Promise<any>} - A promise which resolves to a JSON object with id_token and vp_token as signed strings
     * @remarks This method geenrate id_token and vp_token needed in an authentication response
     * https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0.html#name-response
     */
    static generateResponseWithVPData(requestPayload: any, signingInfo: JWT.SigningInfo, didSiopUser: Identity, expiresIn: number | undefined, vps: VPData): Promise<SIOPTokensEcoded>;
    /**
     * @param {any} requestPayload - Payload of the request JWT. Some information from this object is needed in constructing the header of JWT & keys for signing
     * @param {JWT.SigningInfo} signingInfo - Key information used to sign the response JWT
     * @param {Identity} didSiopUser - Used to retrieve the information about the provider (user DID) which are included in the response
     * response can either consider this value or ignore it
     * @returns {Promise<string>} - A promise which resolves to a response (id_token) (JWT)
     * @remarks This method first checks if given SigningInfo is compatible with the algorithm required by the RP in
     * 'requestPayload.registration.id_token_signed_response_alg' field.
     * Then it proceeds to extract provider's (user) public key from 'didSiopUser' param using 'kid' field in 'signingInfo' param.
     * Finally it will create the response JWT (id_token) with relevant information, sign it using 'signingInfo' and return it.
     * https://identity.foundation/did-siop/#generate-siop-response
     */
    static generateResponseVPToken(requestPayload: any, signingInfo: JWT.SigningInfo, vps?: VPData): Promise<string>;
    /**
     *
     * @param {string} response - A DID SIOP response which needs to be validated
     * @param {CheckParams} checkParams - Specific field values in the JWT which needs to be validated
     * @returns {Promise<JWT.JWTObject | ErrorResponse.SIOPErrorResponse>} - A promise wich will resolve either to a decoded id_token (JWT)
     * or an error response
     * @remarks This method first decodes the response JWT.
     * Then checks if it is an error response and if so, returns it.
     * Else it will proceed to validate the JWT (id_token).
     * Fields in the JWT header and payload will be checked for availability.
     * Then the id_token will be validated against 'checkParams'.
     * Then the signature of the id_token is verified using public key information derived from
     * the 'kid' field in the header and 'did' field in the payload.
     * If the verification is successful, this method returns the decoded id_token (JWT).
     * https://identity.foundation/did-siop/#siop-response-validation
     */
    static validateResponse(response: string, checkParams: CheckParams): Promise<JWT.JWTObject | ErrorResponse.SIOPErrorResponse>;
    static validateResponseWithVPData(tokensEncoded: SIOPTokensEcoded, checkParams: CheckParams): Promise<SIOPTokenObjects | ErrorResponse.SIOPErrorResponse>;
}
