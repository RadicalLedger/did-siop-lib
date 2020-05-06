import { Key, RSAKey, ECKey, OKP } from "./JWKUtils";
import { ALGORITHMS, KEY_FORMATS } from "./globals";
import { createHash, createVerify, constants as cryptoConstants } from 'crypto';
import { eddsa as EdDSA, ec as EC} from 'elliptic';
const publicKeyToAddress = require('ethereum-public-key-to-address');

export const ERRORS = Object.freeze({
    NO_PRIVATE_KEY: 'Not a private key',
    INVALID_ALGORITHM: 'Invalid algorithm',
    INVALID_SIGNATURE: 'Invalid signature',
});

export abstract class Verifier{
    abstract verify(msg: string, signature: Buffer, key: Key | string, algorithm?: ALGORITHMS): boolean;
}

export class RSAVerifier extends Verifier{
    verify(msg: string, signature: Buffer, key: RSAKey, algorithm?: ALGORITHMS | undefined): boolean {
        try {
            let verifier;
            let verifierParams: any = {
                key: key.exportKey(KEY_FORMATS.PKCS8_PEM),
            };
            switch(algorithm){
                case ALGORITHMS.RS256: verifier = createVerify('RSA-SHA256'); break;
                case ALGORITHMS.RS384: verifier = createVerify('RSA-SHA384'); break;
                case ALGORITHMS.RS512: verifier = createVerify('RSA-SHA512'); break;
                case ALGORITHMS.PS256: {
                    verifier = createVerify('RSA-SHA256'); 
                    verifierParams.padding = cryptoConstants.RSA_PKCS1_PSS_PADDING;
                    verifierParams.saltLength = cryptoConstants.RSA_PSS_SALTLEN_DIGEST
                    break;
                }
                case ALGORITHMS.PS384: {
                    verifier = createVerify('RSA-SHA384'); 
                    verifierParams.padding = cryptoConstants.RSA_PKCS1_PSS_PADDING;
                    verifierParams.saltLength = cryptoConstants.RSA_PSS_SALTLEN_DIGEST
                    break;
                }
                case ALGORITHMS.PS512:{
                    verifier = createVerify('RSA-SHA512'); 
                    verifierParams.padding = cryptoConstants.RSA_PKCS1_PSS_PADDING;
                    verifierParams.saltLength = cryptoConstants.RSA_PSS_SALTLEN_DIGEST
                    break;
                }
                default: throw new Error(ERRORS.INVALID_ALGORITHM)
            }

            return verifier.update(msg).verify(verifierParams, signature);
        } catch (err) {
            throw new Error(ERRORS.INVALID_SIGNATURE);
        }
    }

}

export class ECVerifier extends Verifier{
    verify(msg: string, signature: Buffer, key: ECKey, algorithm?: ALGORITHMS | undefined): boolean {
        try {
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

    
            let hash = sha.update(msg).digest();
    
            if (signature.length !== 64) throw new Error(ERRORS.INVALID_SIGNATURE);
            let signatureObj = {
                r: signature.slice(0, 32).toString('hex'),
                s: signature.slice(32, 64).toString('hex')
            }
    
            let ecKey = ec.keyFromPublic(key.exportKey(KEY_FORMATS.HEX), 'hex');
    
            return ecKey.verify(hash, signatureObj);
        } catch (err) {
            throw new Error(ERRORS.INVALID_SIGNATURE);
        }
    }

}

export class OKPVerifier extends Verifier{
    verify(msg: string, signature: Buffer, key: OKP, algorithm?: ALGORITHMS | undefined): boolean {
        try {
            let ed;

            switch(algorithm){
                case ALGORITHMS.EdDSA: {
                    ed = new EdDSA('ed25519'); 
                    break;
                }
                default: throw new Error(ERRORS.INVALID_ALGORITHM);
            }
    
            let edKey = ed.keyFromPublic(key.exportKey(KEY_FORMATS.HEX));
    
            return edKey.verify(Buffer.from(msg), signature.toString('hex'));
        } catch (err) {
            throw new Error(ERRORS.INVALID_SIGNATURE);
        }
    }
}

export class ES256KRecoverableVerifier extends Verifier{
    verify(msg: string, signature: Buffer, key: string): boolean {
        let sha = createHash('sha256');
        let ec = new EC('secp256k1');

        let hash = sha.update(msg).digest();

        if (signature.length !== 65) throw new Error(ERRORS.INVALID_SIGNATURE);
        let signatureObj = {
            r: signature.slice(0, 32).toString('hex'),
            s: signature.slice(32, 64).toString('hex'),
        }
        let recoveredKey = ec.recoverPubKey(hash, signatureObj, signature[64]);
        return (
            recoveredKey.encode('hex') === key ||
            recoveredKey.encode('hex', true) === key ||
            publicKeyToAddress(recoveredKey.encode('hex')) === key
        )
    }

}