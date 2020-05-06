import { createHash, createSign, constants as cryptoConstants } from 'crypto';
import { leftpad } from './Utils';
import { Key, RSAKey, ECKey, OKP } from './JWKUtils';
import { ALGORITHMS, KEY_FORMATS } from './globals';
import { eddsa as EdDSA, ec as EC} from 'elliptic';

export const ERRORS = Object.freeze({
    NO_PRIVATE_KEY: 'Not a private key',
    INVALID_ALGORITHM: 'Invalid algorithm',
});

export abstract class Signer{
    abstract sign(message: string, key: Key | string,  algorithm?: ALGORITHMS): Buffer;
}

export class RSASigner extends Signer{
    sign(message: string, key: RSAKey, algorithm: ALGORITHMS): Buffer {
        if(key.isPrivate()){
            let signer;
            let signerParams: any = {
                key: key.exportKey(KEY_FORMATS.PKCS8_PEM),
            };
            switch(algorithm){
                case ALGORITHMS.RS256: signer = createSign('RSA-SHA256'); break;
                case ALGORITHMS.RS384: signer = createSign('RSA-SHA384'); break;
                case ALGORITHMS.RS512: signer = createSign('RSA-SHA512'); break;
                case ALGORITHMS.PS256: {
                    signer = createSign('RSA-SHA256'); 
                    signerParams.padding = cryptoConstants.RSA_PKCS1_PSS_PADDING;
                    signerParams.saltLength = cryptoConstants.RSA_PSS_SALTLEN_DIGEST
                    break;
                }
                case ALGORITHMS.PS384: {
                    signer = createSign('RSA-SHA384'); 
                    signerParams.padding = cryptoConstants.RSA_PKCS1_PSS_PADDING;
                    signerParams.saltLength = cryptoConstants.RSA_PSS_SALTLEN_DIGEST
                    break;
                }
                case ALGORITHMS.PS512:{
                    signer = createSign('RSA-SHA512'); 
                    signerParams.padding = cryptoConstants.RSA_PKCS1_PSS_PADDING;
                    signerParams.saltLength = cryptoConstants.RSA_PSS_SALTLEN_DIGEST
                    break;
                }
                default: throw new Error(ERRORS.INVALID_ALGORITHM)
            }
            
            return signer.update(message).sign(signerParams);
        }
        else{
            throw new Error(ERRORS.NO_PRIVATE_KEY);
        }
    }

}

export class ECSigner extends Signer{
    sign(message: string, key: ECKey, algorithm: ALGORITHMS): Buffer {
        if(key.isPrivate()){
            let sha;
            let ec;

            switch(algorithm){
                case ALGORITHMS.ES256: {
                    sha = createHash('sha256'); 
                    ec = new EC('p256'); 
                    break;
                }
                case ALGORITHMS.ES384: {
                    sha = createHash('sha384'); 
                    ec = new EC('p384'); 
                    break;
                }
                case ALGORITHMS.ES512: {
                    sha = createHash('sha512'); 
                    ec = new EC('p512'); 
                    break;
                }
                case ALGORITHMS.ES256K: {
                    sha = createHash('sha256'); 
                    ec = new EC('secp256k1'); 
                    break;
                }
                case ALGORITHMS.EdDSA: {
                    sha = createHash('sha256'); 
                    ec = new EC('ed25519'); 
                    break;
                }
                default: throw new Error(ERRORS.INVALID_ALGORITHM);
            }

            let hash = sha.update(message).digest('hex');

            let ecKey = ec.keyFromPrivate(key.exportKey(KEY_FORMATS.HEX));

            let ec256k_signature = ecKey.sign(hash);

            let signature = Buffer.alloc(64);
            Buffer.from(leftpad(ec256k_signature.r.toString('hex')), 'hex').copy(signature, 0);
            Buffer.from(leftpad(ec256k_signature.s.toString('hex')), 'hex').copy(signature, 32);

            return signature;
        }
        else{
            throw new Error(ERRORS.NO_PRIVATE_KEY);
        }
    }
    
}

export class OKPSigner extends Signer{
    sign(message: string, key: OKP, algorithm: ALGORITHMS): Buffer {
        if(key.isPrivate()){
            let ed;

            switch(algorithm){
                case ALGORITHMS.EdDSA: {
                    ed = new EdDSA('ed25519'); 
                    break;
                }
                default: throw new Error(ERRORS.INVALID_ALGORITHM);
            }

            let edKey = ed.keyFromSecret(key.exportKey(KEY_FORMATS.HEX));

            let edDsa_signature = edKey.sign(Buffer.from(message));
            return Buffer.from(edDsa_signature.toHex(), 'hex');
        }
        else{
            throw new Error(ERRORS.NO_PRIVATE_KEY);
        }
    }

}

export class ES256KRecoverableSigner extends Signer{
    sign(message: string, key: ECKey | string): Buffer {
        let keyHexString;
        if(typeof key === 'string'){
            keyHexString = key;
        }
        else{
            keyHexString = key.exportKey(KEY_FORMATS.HEX);
        }

        let sha = createHash('sha256'); 
        let ec = new EC('secp256k1'); 

        let hash = sha.update(message).digest('hex');

        let signingKey = ec.keyFromPrivate(keyHexString);

        let ec256k_signature = signingKey.sign(hash);

        let jose = Buffer.alloc(ec256k_signature.recoveryParam? 65 : 64);
        Buffer.from(leftpad(ec256k_signature.r.toString('hex')), 'hex').copy(jose, 0);
        Buffer.from(leftpad(ec256k_signature.s.toString('hex')), 'hex').copy(jose, 32);
        if (ec256k_signature.recoveryParam) jose[64] = ec256k_signature.recoveryParam;

        return jose;
    }

}