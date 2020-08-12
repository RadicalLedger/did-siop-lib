import { DidDocument, DidVerificationKey } from './commons';
import { DidVerificationKeyExtractor } from './key-extractors';
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
export { DidDocument, DidVerificationKey, DidVerificationKeyMethod, ERRORS } from './commons';
export { DidVerificationKeyExtractor, uniExtractor } from './key-extractors';
