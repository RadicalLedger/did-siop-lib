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
export declare function sign(jwtObject: JWTObject, signingInfo: SigningInfo): string;
export declare function verify(jwt: string, signingInfo: SigningInfo): boolean;
