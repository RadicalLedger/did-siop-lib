import { KEY_FORMATS, KTYS, ALGORITHMS } from './globals';
export interface DidDocument {
    '@context': any;
    id: string;
    authentication: any[];
    [propName: string]: any;
}
interface DidVerificationKeyMethod {
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
export declare class Identity {
    private doc;
    private keySet;
    constructor();
    resolve(did: string): Promise<string>;
    isResolved(): boolean;
    extractAuthenticationKeys(extractor?: DidVerificationKeyExtractor): DidVerificationKey[];
    getDocument(): DidDocument;
    setDocument(doc: DidDocument, did: string): void;
}
export declare abstract class DidVerificationKeyExtractor {
    protected names: string[];
    protected next: DidVerificationKeyExtractor | EmptyDidVerificationKeyExtractor;
    constructor(names: string | string[], next?: DidVerificationKeyExtractor);
    abstract extract(method: DidVerificationKeyMethod): DidVerificationKey;
}
declare class EmptyDidVerificationKeyExtractor {
    extract(method: DidVerificationKeyMethod): DidVerificationKey;
}
declare class UniversalDidPublicKeyExtractor extends DidVerificationKeyExtractor {
    extract(method: DidVerificationKeyMethod): DidVerificationKey;
}
export declare const uniExtractor: UniversalDidPublicKeyExtractor;
export {};
