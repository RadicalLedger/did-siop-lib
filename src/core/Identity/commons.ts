import { KTYS } from "../globals";
import { ALGORITHMS, KEY_FORMATS } from "../..";

export interface DidDocument{
    '@context': any;
    id: string;
    authentication: any[];
    [propName:string]: any;
}

export interface DidVerificationKeyMethod{
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

export interface DidVerificationKey{
    id: string;
    kty: KTYS;
    alg: ALGORITHMS,
    format: KEY_FORMATS;
    publicKey: any;
}

export const ERRORS = Object.freeze(
    {
        DOCUMENT_RESOLUTION_ERROR: 'Cannot resolve document for did',
        INVALID_DID_ERROR: 'Invalid did',
        UNSUPPORTED_KEY_TYPE: 'Unsupported key type',
        UNSUPPORTED_KEY_FORMAT: 'Unsupported key format',
        NO_MATCHING_PUBLIC_KEY: 'No public key matching kid',
        UNSUPPORTED_PUBLIC_KEY_METHOD: 'Unsupported public key method',
        UNRESOLVED_DOCUMENT: 'Unresolved document',
        INVALID_DOCUMENT: 'Invalid did document',
    }
);