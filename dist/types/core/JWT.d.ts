/// <reference types="node" />
import { ALGORITHMS, KEY_FORMATS } from './globals';
export interface JWTHeader {
    typ: string;
    alg: string;
    kid: string;
}
export interface JWTObject {
    header: JWTHeader;
    payload: any;
}
export interface JWTSignedObject extends JWTObject {
    signed: string;
    signature: Buffer;
}
export interface SigningInfo {
    alg: ALGORITHMS;
    kid: string;
    key: string;
    format: KEY_FORMATS;
}
export declare const ERRORS: Readonly<{
    UNSUPPORTED_ALGORITHM: string;
    ALGORITHM_MISMATCH: string;
    INVALID_JWT: string;
    INVALID_SIGNATURE: string;
}>;
/**
 * @param {JWTObject} jwtObject - JWT which needs to be signed
 * @param {SigningInfo} signingInfo - Information about signing key and algorithm
 * @returns {string} - A signed JWT (JWS) https://tools.ietf.org/html/rfc7515
 * @remarks This method first checks for the validity of signingInfo and header part of jwtObject.
 * If information provided are valid then jwtObject will be signed with an appropriate Signer and the
 * signed object (encoded jwt + signature) (JWS) will be returned.
 */
export declare function sign(jwtObject: JWTObject, signingInfo: SigningInfo): string;
/**
 * @param {sting} jwt - A signed and encoded jwt (JWS) which needs to be verified.
 * @param {SigningInfo} signingInfo - Information about verification key and algorithm
 * @returns {boolean} - A boolean which indicates whether JWS is verifiable with given information.
 * @remarks This method first decodes the JWT and then checks for the validity of signingInfo and header part of jwtObject.
 * If information provided are valid then jwt will be verified using the related Verifier and the resulting boolean value will be
 * returned.
 */
export declare function verify(jwt: string, signingInfo: SigningInfo): boolean;
