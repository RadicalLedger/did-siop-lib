import { ALGORITHMS, KTYS, KEY_FORMATS } from './globals';
import * as JWT from './JWT';
import { Identity } from './Identity';
import { KeyInputs, Key, RSAKey, ECKey, OKP, calculateThumbprint } from './JWKUtils';
import base64url from 'base64url';
import * as ErrorResponse from './ErrorResponse';


const ERRORS = Object.freeze({
    UNSUPPORTED_ALGO: 'Algorithm not supported',
    PUBLIC_KEY_ERROR: 'Cannot resolve public key',
    KEY_MISMATCH: 'Signing key does not match kid',
    MALFORMED_JWT_ERROR: 'Malformed response jwt',
    NON_SIOP_FLOW: 'Response jwt is not compatible with SIOP flow',
    INCORRECT_AUDIENCE: 'Incorrect audience',
    INCORRECT_NONCE: 'Incorrect nonce',
    NO_ISSUED_TIME: 'No iat in jwt',
    NO_EXPIRATION: 'No exp in jwt',
    JWT_VALIDITY_EXPIRED: 'JWT validity has expired',
    INVALID_JWK_THUMBPRINT: 'Invalid sub (sub_jwk thumbprint)',
    INVALID_SIGNATURE_ERROR: 'Invalid signature error',
});

export interface CheckParams{
    redirect_uri: string,
    nonce?: string,
    validBefore?: number,
    isExpirable?: boolean,
}

export class DidSiopResponse{
    static async generateResponse(requestPayload: any, signingInfo: JWT.SigningInfo, didSiopUser: Identity, expiresIn: number = 1000): Promise<string>{
        try {
            let header: JWT.JWTHeader;
            let alg = '';
        
            if (requestPayload.registration.id_token_signed_response_alg.includes(ALGORITHMS[signingInfo.alg])){
                alg = ALGORITHMS[signingInfo.alg];
            }
            else{
                Promise.reject(ERRORS.UNSUPPORTED_ALGO);
            }

            let didPubKey = didSiopUser.getPublicKey(signingInfo.publicKey_kid);
            header = {
                typ: 'JWT',
                alg: alg,
                kid: signingInfo.publicKey_kid,
            }

            let publicKey: Key | undefined;

            let keyInfo: KeyInputs.KeyInfo = {
                key: didPubKey.keyString,
                kid: didPubKey.id,
                use: 'sig',
                kty: KTYS[didPubKey.kty],
                format: didPubKey.format,
                isPrivate: false,
            }

            switch(didPubKey.kty){
                case KTYS.RSA: publicKey = RSAKey.fromKey(keyInfo); break;
                case KTYS.EC: {
                    if(didPubKey.format === KEY_FORMATS.ETHEREUM_ADDRESS){
                        publicKey = signingInfo.privateKey; 
                    }
                    else{
                        publicKey = ECKey.fromKey(keyInfo); 
                    }
                    break;
                }
                case KTYS.OKP: publicKey = OKP.fromKey(keyInfo); break;
            }
    
            let payload: any = {
                iss: 'https://self-issued.me',
            }
    
            payload.did = didSiopUser.getDocument().id;
            if(requestPayload.client_id) payload.aud = requestPayload.client_id;
    
            if(publicKey){
                payload.sub_jwk = publicKey.getMinimalJWK();
                payload.sub = calculateThumbprint(publicKey.getMinimalJWK());
            }
            else{
                return Promise.reject(new Error(ERRORS.PUBLIC_KEY_ERROR));
            }
    
            if (requestPayload.nonce) payload.nonce = requestPayload.nonce;
            if (requestPayload.state) payload.state = requestPayload.state;
    
            payload.iat = Date.now();
            payload.exp = Date.now() + expiresIn;

            let unsigned: JWT.JWTObject = {
                header: header,
                payload: payload,
            }
    
            return JWT.sign(unsigned, signingInfo.privateKey);
        } catch (err) {
            return Promise.reject(err);
        }
    }

    static async validateResponse(response: string, checkParams: CheckParams): Promise<JWT.JWTObject | ErrorResponse.SIOPErrorResponse>{
        let decodedHeader;
        let decodedPayload;
        try {
            let errorResponse = ErrorResponse.checkErrorResponse(response);
            if(errorResponse) return errorResponse;

            decodedHeader = JSON.parse(base64url.decode(response.split('.')[0]));
            decodedPayload = JSON.parse(base64url.decode(response.split('.')[1]));
        } catch (err) {
            return Promise.reject(err);
        }

        if(
            (decodedHeader.kid && !decodedHeader.kid.match(/^ *$/)) &&
            (decodedPayload.iss && !decodedPayload.iss.match(/^ *$/)) &&
            (decodedPayload.aud && !decodedPayload.aud.match(/^ *$/)) &&
            (decodedPayload.did && !decodedPayload.did.match(/^ *$/)) &&
            (decodedPayload.sub && !decodedPayload.sub.match(/^ *$/)) &&
            (decodedPayload.sub_jwk && !JSON.stringify(decodedPayload.sub_jwk).match(/^ *$/))
        ){
            if (decodedPayload.iss !== 'https://self-issued.me') return Promise.reject(new Error(ERRORS.NON_SIOP_FLOW));

            if (decodedPayload.aud !== checkParams.redirect_uri) return Promise.reject(new Error(ERRORS.INCORRECT_AUDIENCE));

            if (decodedPayload.nonce && (decodedPayload.nonce !== checkParams.nonce)) return Promise.reject(new Error(ERRORS.INCORRECT_NONCE)); 

            if(checkParams.validBefore){
                if(decodedPayload.iat){
                    if (decodedPayload.iat + checkParams.validBefore <= Date.now()) return Promise.reject(new Error(ERRORS.JWT_VALIDITY_EXPIRED));
                }
                else{
                    return Promise.reject(new Error(ERRORS.NO_ISSUED_TIME));
                }
            }

            if(checkParams.isExpirable){
                if (decodedPayload.exp) {
                    if (decodedPayload.exp <= Date.now()) return Promise.reject(new Error(ERRORS.JWT_VALIDITY_EXPIRED));
                } else {
                    return Promise.reject(new Error(ERRORS.NO_EXPIRATION));
                }
            }

            let jwkThumbprint = calculateThumbprint(decodedPayload.sub_jwk);
            if (jwkThumbprint !== decodedPayload.sub) return Promise.reject(new Error(ERRORS.INVALID_JWK_THUMBPRINT));

            
            let publicKey: Key | string | undefined;
            try{
                let identity = new Identity();
                await identity.resolve(decodedPayload.did);
                

                let didPubKey = identity.getPublicKey(decodedHeader.kid);
            
                let keyInfo: KeyInputs.KeyInfo = {
                    key: didPubKey.keyString,
                    kid: didPubKey.id,
                    use: 'sig',
                    kty: KTYS[didPubKey.kty],
                    format: didPubKey.format,
                    isPrivate: false,
                }
    
                switch(didPubKey.kty){
                    case KTYS.RSA: publicKey = RSAKey.fromKey(keyInfo); break;
                    case KTYS.EC: {
                        if(didPubKey.format === KEY_FORMATS.ETHEREUM_ADDRESS){
                            publicKey = keyInfo.key; 
                        }
                        else{
                            publicKey = ECKey.fromKey(keyInfo); 
                        }
                        break;
                    }
                    case KTYS.OKP: publicKey = OKP.fromKey(keyInfo); break;
                }
            }
            catch(err){
                return Promise.reject(ERRORS.PUBLIC_KEY_ERROR);
            }

            let validity: boolean = false; 
            if(publicKey){
                validity = JWT.verify(response, publicKey);
            }
            else{
                return Promise.reject(ERRORS.PUBLIC_KEY_ERROR);
            }
            
            if(validity) return {
                header: decodedHeader,
                payload: decodedPayload,
            }

            return Promise.reject(new Error(ERRORS.INVALID_SIGNATURE_ERROR));
        }
        else {
            return Promise.reject(new Error(ERRORS.MALFORMED_JWT_ERROR));
        }
    }
}
