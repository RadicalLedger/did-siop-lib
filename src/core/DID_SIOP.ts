import { RSAVerifier, ECVerifier, OKPVerifier, ES256KRecoverableVerifier } from './Verifiers';
import { RSASigner, ECSigner, OKPSigner, ES256KRecoverableSigner } from './Signers';
import { Key, RSAKey, OKP, ECKey, KeyInputs } from './JWKUtils';
import { KEY_FORMATS, ALGORITHMS, KTYS } from './globals';
import { DidSiopResponse } from './Response';
import { SigningInfo, JWTObject } from './JWT';
import { Identity, DidDocument } from './Identity';
import { DidSiopRequest } from './Request';
import { checkKeyPair } from './Utils';

const ERRORS= Object.freeze({
    NO_SIGNING_INFO: 'Atleast one SigningInfo is required',
    UNRESOLVED_IDENTITY: 'Unresolved identity',
    INVALID_KEY_TYPE: 'Invalid key type',
    KEY_MISMATCH: 'Public and private keys do not match',
});

export class SIOP{
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

    addSigningParams(key: string, kid: string, format: KEY_FORMATS, algorithm: ALGORITHMS) {
        try{
            let didPublicKey = this.identity.getPublicKey(kid);

            let publicKeyInfo: KeyInputs.KeyInfo = {
                key: didPublicKey.keyString,
                kid,
                use: 'sig',
                kty: KTYS[didPublicKey.kty],
                alg: ALGORITHMS[algorithm],
                format: didPublicKey.format,
                isPrivate: false
            }

            let privateKeyInfo: KeyInputs.KeyInfo = {
                key: key,
                kid,
                use: 'sig',
                kty: KTYS[didPublicKey.kty],
                alg: ALGORITHMS[algorithm],
                format: format,
                isPrivate: true
            }

            let privateKey: Key;
            let publicKey: Key | string;
            let signer, verifier;

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
                        publicKey = didPublicKey.keyString;
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
                    throw new Error(ERRORS.INVALID_KEY_TYPE);
                }
            }

            if(checkKeyPair(privateKey, publicKey, signer, verifier, algorithm)){
                this.signing_info_set.push({
                    alg: algorithm,
                    publicKey_kid: kid,
                    privateKey: privateKey
                })
            }
            else{
                throw new Error(ERRORS.KEY_MISMATCH);
            }
            
        }
        catch(err){
            throw err;
        }
    }

    removeSigningParams(kid: string){
        try{
            this.signing_info_set = this.signing_info_set.filter(s => { return s.publicKey_kid !== kid });
        }
        catch(err){
            throw err;
        }
    }

    async validateRequest(request: string): Promise<JWTObject>{
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
}