import { KEY_FORMATS, KTYS } from './globals';
export interface DidDocument {
    '@context': string;
    id: string;
    authentication: any[];
    [propName: string]: any;
}
export interface DidPublicKey {
    id: string;
    kty: KTYS;
    format: KEY_FORMATS;
    keyString: string;
}
export declare const ERRORS: Readonly<{
    DOCUMENT_RESOLUTION_ERROR: string;
    INVALID_DID_ERROR: string;
    UNSUPPORTED_KEY_TYPE: string;
    UNSUPPORTED_KEY_FORMAT: string;
    NO_MATCHING_PUBLIC_KEY: string;
    UNRESOLVED_DOCUMENT: string;
    INVALID_DOCUMENT: string;
}>;
export declare class Identity {
    private doc;
    constructor();
    resolve(did: string): Promise<string>;
    isResolved(): boolean;
    getPublicKey(kid: string): DidPublicKey;
    getDocument(): DidDocument;
    setDocument(doc: DidDocument, did: string): void;
}
