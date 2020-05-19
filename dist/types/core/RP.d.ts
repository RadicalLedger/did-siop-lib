import { CheckParams } from './Response';
import { DidDocument } from './Identity';
import { KEY_FORMATS, ALGORITHMS } from './globals';
export declare class RP {
    private info;
    private identity;
    private signing_info_set;
    private constructor();
    static getRP(redirect_uri: string, did: string, registration: any, did_doc?: DidDocument): Promise<RP>;
    addSigningParams(key: string, kid: string, format: KEY_FORMATS | string, algorithm: ALGORITHMS | string): void;
    removeSigningParams(kid: string): void;
    generateRequest(options?: any): Promise<string>;
    generateUriRequest(request_uri: string, options?: any): Promise<string>;
    validateResponse(response: string, checkParams?: CheckParams): Promise<any>;
}
