import { DidSiopResponse, CheckParams } from './Response';
import { RPInfo, DidSiopRequest } from './Request';
import { SigningInfo, JWTObject } from './JWS';
import { DidDocument, Identity } from './Identity';
import { KEY_FORMATS, ALGORITHMS, KTYS } from './globals';
import { KeyInputs, Key, RSAKey, ECKey, OKP } from './JWKUtils';
import { RSASigner, ES256KRecoverableSigner, ECSigner, OKPSigner } from './Signers';
import { RSAVerifier, ES256KRecoverableVerifier, ECVerifier, OKPVerifier } from './Verifiers';
import { checkKeyPair } from './Utils';
import { SIOPErrorResponse } from './ErrorResponse';

export const ERRORS= Object.freeze({
    NO_SIGNING_INFO: 'At least one public key must be confirmed with related private key',
    NO_PUBLIC_KEY: 'No public key matches given private key',
});

export class RP {
    private info: RPInfo;
    private identity: Identity = new Identity();
    private signing_info_set: SigningInfo[] = [];

    private constructor(redirect_uri: string, did: string, registration: any, did_doc?: DidDocument) {
        this.info = {
            redirect_uri,
            did,
            registration,
            did_doc
        }
    }

    static async getRP(redirect_uri: string, did: string, registration: any, did_doc?: DidDocument): Promise<RP> {
        try {
            let rp = new RP(redirect_uri, did, registration, did_doc)
            if(did_doc){
                rp.identity.setDocument(did_doc, did);
            }
            else{
                await rp.identity.resolve(did);
            }
            return rp;
        } catch (err) {
            return Promise.reject(err);
        }
    }

    addSigningParams(key: string, kid?: string, format?: KEY_FORMATS | string, algorithm?: ALGORITHMS | string): string {
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

    async generateRequest(options:any = {}): Promise<string> {
        try{
            if(this.signing_info_set.length > 0){
                let signing_info = this.signing_info_set[Math.floor(Math.random() * this.signing_info_set.length)];
                return await DidSiopRequest.generateRequest(this.info, signing_info, options);
            }
            return Promise.reject(new Error(ERRORS.NO_SIGNING_INFO));
        }
        catch(err){
            return Promise.reject(err);
        }
    }

    async generateUriRequest(request_uri: string, options:any = {}): Promise<string> {
        try{
            this.info.request_uri = request_uri;
            return await this.generateRequest(options);
        }
        catch(err){
            return Promise.reject(ERRORS.NO_SIGNING_INFO);
        }
    }

    async validateResponse(response: string, checkParams: CheckParams = {redirect_uri: this.info.redirect_uri}): Promise<JWTObject | SIOPErrorResponse> {
        try {
            return await DidSiopResponse.validateResponse(response, checkParams);
        } catch (err) {
            return Promise.reject(err);
        }
    }
}
