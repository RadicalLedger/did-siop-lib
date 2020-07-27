import { CheckParams } from './Response';
import { JWTObject } from './JWT';
import { DidDocument } from './Identity';
import { KEY_FORMATS, ALGORITHMS } from './globals';
import { SIOPErrorResponse } from './ErrorResponse';
export declare const ERRORS: Readonly<{
    NO_SIGNING_INFO: string;
    NO_PUBLIC_KEY: string;
}>;
export declare class RP {
    private info;
    private identity;
    private signing_info_set;
    private constructor();
    static getRP(redirect_uri: string, did: string, registration: any, did_doc?: DidDocument): Promise<RP>;
    addSigningParams(key: string, kid?: string, format?: KEY_FORMATS | string, algorithm?: ALGORITHMS | string): string;
    removeSigningParams(kid: string): void;
    generateRequest(options?: any): Promise<string>;
    generateUriRequest(request_uri: string, options?: any): Promise<string>;
    validateResponse(response: string, checkParams?: CheckParams): Promise<JWTObject | SIOPErrorResponse>;
}
