import { DidVerificationKeyMethod, DidVerificationKey } from "./commons";
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
