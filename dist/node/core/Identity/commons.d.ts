import { KTYS } from "../globals";
import { ALGORITHMS, KEY_FORMATS } from "../..";
export interface DidDocument {
    '@context': any;
    id: string;
    authentication: any[];
    [propName: string]: any;
}
export interface DidVerificationKeyMethod {
    id: string;
    type: string;
    publicKeyBase58?: string;
    publicKeyBase64?: string;
    publicKeyHex?: string;
    publicKeyPem?: string;
    publicKeyJwk?: any;
    publicKeyGpg?: string;
    ethereumAddress?: string;
    address?: string;
    [propName: string]: any;
}
export interface DidVerificationKey {
    id: string;
    kty: KTYS;
    alg: ALGORITHMS;
    format: KEY_FORMATS;
    publicKey: any;
}
export declare const ERRORS: Readonly<{
    DOCUMENT_RESOLUTION_ERROR: string;
    INVALID_DID_ERROR: string;
    UNSUPPORTED_KEY_TYPE: string;
    UNSUPPORTED_KEY_FORMAT: string;
    NO_MATCHING_PUBLIC_KEY: string;
    UNSUPPORTED_PUBLIC_KEY_METHOD: string;
    UNRESOLVED_DOCUMENT: string;
    INVALID_DOCUMENT: string;
}>;
