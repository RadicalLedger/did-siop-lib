import { KEY_FORMATS, ALGORITHMS } from './globals';
import { JWTObject } from './JWT';
import { DidDocument } from './Identity';
export declare const ERRORS: Readonly<{
    NO_SIGNING_INFO: string;
    UNRESOLVED_IDENTITY: string;
    NO_PUBLIC_KEY: string;
}>;
export declare class Provider {
    private identity;
    private signing_info_set;
    setUser(did: string, doc?: DidDocument): Promise<void>;
    addSigningParams(key: string, kid?: string, format?: KEY_FORMATS | string, algorithm?: ALGORITHMS | string): string;
    removeSigningParams(kid: string): void;
    validateRequest(request: string): Promise<JWTObject>;
    generateResponse(requestPayload: any, expiresIn?: number): Promise<string>;
    generateErrorResponse(errorMessage: string): string;
}
