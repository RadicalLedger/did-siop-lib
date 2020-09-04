import { RSAVerifier, ECVerifier, OKPVerifier, ES256KRecoverableVerifier } from './Verifiers';
import { RSASigner, ECSigner, OKPSigner, ES256KRecoverableSigner } from './Signers';
import { Key, RSAKey, OKP, ECKey, KeyInputs } from './JWKUtils';
import { KEY_FORMATS, ALGORITHMS, KTYS } from './globals';
import { DidSiopResponse } from './Response';
import { SigningInfo, JWSObject } from './JWS';
import { Identity, DidDocument } from './Identity';
import { DidSiopRequest } from './Request';
import { checkKeyPair } from './Utils';
import * as ErrorResponse from './ErrorResponse';

export const ERRORS= Object.freeze({
    NO_SIGNING_INFO: 'At least one public key must be confirmed with related private key',
    UNRESOLVED_IDENTITY: 'Unresolved identity',
    NO_PUBLIC_KEY: 'No public key matches given private key',
});

export class Provider{
    private identity: Identity = new Identity();
    private signing_info_set: SigningInfo[] = [];

    async setUser(did: string, doc?: DidDocument){
        try {
            if(doc){
                this.identity.setDocument(doc, did);
            }
            else{
                await this.identity.resolve(did);
            }
        } catch (err) {
            throw err;
        }
    }

    addSigningParams(key: string, kid?: string, format?: KEY_FORMATS | string, algorithm?: ALGORITHMS | string): string{
        try{
            if(format){}
            if(algorithm){}
            if(kid){}

            let didPublicKeySet = this.identity.extractAuthenticationKeys();

            for(let didPublicKey of didPublicKeySet){
                let publicKeyInfo: KeyInputs.KeyInfo = {
                    key: didPublicKey.publicKey,
                    kid: didPublicKey.id,
                    use: 'sig',
                    kty: KTYS[didPublicKey.kty],
                    alg: ALGORITHMS[didPublicKey.alg],
                    format: didPublicKey.format,
                    isPrivate: false
                }
    
                for(let key_format in KEY_FORMATS){

                    let privateKeyInfo: KeyInputs.KeyInfo = {
                        key: key,
                        kid: didPublicKey.id,
                        use: 'sig',
                        kty: KTYS[didPublicKey.kty],
                        alg: ALGORITHMS[didPublicKey.alg],
                        format: KEY_FORMATS[key_format as keyof typeof KEY_FORMATS],
                        isPrivate: true
                    }
        
                    let privateKey: Key;
                    let publicKey: Key | string;
                    let signer, verifier;
        
                    try{
                        switch(didPublicKey.kty){
                            case KTYS.RSA: {
                                privateKey = RSAKey.fromKey(privateKeyInfo);
                                publicKey = RSAKey.fromKey(publicKeyInfo);
                                signer = new RSASigner();
                                verifier = new RSAVerifier();
                                break;
                            };
                            case KTYS.EC: {
                                if(didPublicKey.format === KEY_FORMATS.ETHEREUM_ADDRESS){
                                    privateKey = ECKey.fromKey(privateKeyInfo);
                                    publicKey = didPublicKey.publicKey;
                                    signer = new ES256KRecoverableSigner();
                                    verifier = new ES256KRecoverableVerifier();
                                }
                                else{
                                    privateKey = ECKey.fromKey(privateKeyInfo);
                                    publicKey = ECKey.fromKey(publicKeyInfo);
                                    signer = new ECSigner();
                                    verifier = new ECVerifier();
                                }
                                break;
                            }
                            case KTYS.OKP: {
                                privateKey = OKP.fromKey(privateKeyInfo);
                                publicKey = OKP.fromKey(publicKeyInfo);
                                signer = new OKPSigner();
                                verifier = new OKPVerifier();
                                break;
                            };
                            default:{
                                continue;
                            }
                        }
            
                        if(checkKeyPair(privateKey, publicKey, signer, verifier, didPublicKey.alg)){
                            this.signing_info_set.push({
                                alg: didPublicKey.alg,
                                kid: didPublicKey.id,
                                key: key,
                                format: KEY_FORMATS[key_format as keyof typeof KEY_FORMATS],
                            })
                            return didPublicKey.id;
                        }
                    }
                    catch(err){
                        continue;
                    }
                }
            }
            throw new Error(ERRORS.NO_PUBLIC_KEY);
        }
        catch(err){
            throw err;
        }
    }

    removeSigningParams(kid: string){
        try{
            this.signing_info_set = this.signing_info_set.filter(s => { return s.kid !== kid });
        }
        catch(err){
            throw err;
        }
    }

    async validateRequest(request: string): Promise<JWSObject>{
        try {
            return DidSiopRequest.validateRequest(request);
        } catch (err) {
            return Promise.reject(err);
        }
    }

    async generateResponse(requestPayload: any, expiresIn: number = 1000): Promise<string>{
        try{
            if(this.signing_info_set.length > 0){
                let signing_info = this.signing_info_set[Math.floor(Math.random() * this.signing_info_set.length)];

                if(this.identity.isResolved()){
                    return await DidSiopResponse.generateResponse(requestPayload, signing_info, this.identity, expiresIn);
                }
                else{
                    return Promise.reject(new Error(ERRORS.UNRESOLVED_IDENTITY));
                }
            }
            return Promise.reject(new Error(ERRORS.NO_SIGNING_INFO));
        }
        catch(err){
            return Promise.reject(err);
        }
    }

    generateErrorResponse(errorMessage: string): string{
        try{
            return ErrorResponse.getBase64URLEncodedError(errorMessage);
        }
        catch(err){
            throw err;
        }
    }
}