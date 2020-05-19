import * as JWT from './JWT';
import { Identity } from './Identity';
import * as ErrorResponse from './ErrorResponse';
export interface CheckParams {
    redirect_uri: string;
    nonce?: string;
    validBefore?: number;
    isExpirable?: boolean;
}
export declare class DidSiopResponse {
    static generateResponse(requestPayload: any, signingInfo: JWT.SigningInfo, didSiopUser: Identity, expiresIn?: number): Promise<string>;
    static validateResponse(response: string, checkParams: CheckParams): Promise<JWT.JWTObject | ErrorResponse.SIOPErrorResponse>;
}
