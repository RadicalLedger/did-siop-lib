import { JWTObject } from '../JWT';
/** @param {any} decodedPayload - Decoded payload of the JWT
 * @returns {boolean>} - true if all optional parameters are valid, false otherwise
 * @remarks This method is used to validate optional elements of the Authentication Request.
 * Currently valuidates claims/vp_token property if exist
 * https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0.html#name-vp_token
 */
export declare function validateRequestJWTClaims(decodedPayload: any): Promise<any>;
export declare function validateResponseVPToken(vp_token: any): Promise<any>;
export declare function validateResponseVPTokenJWT(vp_tokenJWT: JWTObject): Promise<any>;
export declare function validateResponse_VPToken(_vp_token: any): Promise<any>;
export { VPData, SIOPTokensEcoded, SIOPTokenObjects } from './commons';
