import { DidDocument } from './Identity';
import * as JWT from './JWT';
export interface RPInfo {
    redirect_uri: string;
    did: string;
    registration: any;
    did_doc?: DidDocument;
    request_uri?: string;
}
export declare class DidSiopRequest {
    static validateRequest(request: string): Promise<JWT.JWTObject>;
    static generateRequest(rp: RPInfo, signingInfo: JWT.SigningInfo, options: any): Promise<string>;
}
