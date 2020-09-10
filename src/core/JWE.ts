import { Key, ECKey, OKP } from "./JWKUtils";
import base64url from 'base64url';
import { KTYS, KEY_FORMATS, ALGORITHMS } from "./globals";
import { ec as EC } from 'elliptic';
import { createECDH } from 'crypto';
const NodeRSA = require('node-rsa');

export interface JWEHeader{
    alg: string,
    epk: any,
    enc: string,
    kid: string,
}

export interface EncryptionInfo{
    alg: ALGORITHMS;
    kid: string;
    key: string;
    format: KEY_FORMATS;
}

export interface JWTEncryptedObject{
    header: JWEHeader;
    iv: Buffer;
    ciphertext: Buffer;
    auth_tag: Buffer,
}

export const ERRORS = Object.freeze({
    INVALID_JWE: 'Invalid JWE',
    UNSUPPORTED_CURVE: 'Unsupported curve',
});

function decodeJWT(jwe: string): JWTEncryptedObject{
    try {
        let header = JSON.parse(base64url.decode(jwe.split('.')[0]));
        let iv = base64url.toBuffer(jwe.split('.')[2]);
        let ciphertext = base64url.toBuffer(jwe.split('.')[3]);
        let auth_tag = base64url.toBuffer(jwe.split('.')[4]);
    
        return {
            header,
            iv,
            ciphertext,
            auth_tag,
        }
    } catch (err) {
        throw new Error(ERRORS.INVALID_JWE);
    }
}

abstract class DHSecretGenerator{
    abstract generate(publicKey: Key, ephemeralKeyPair?: Key): any;
    abstract regenerate(privateKey: Key, ephemeralPublicKey: Key): Buffer;
}

class ECDHSecretGenerator extends DHSecretGenerator{
    
    private curves = ['secp256k1', 'p192', 'p224', 'p256', 'p384', 'p521', 'curve25519'];

    generate(publicKey: ECKey | OKP, ephemeralPrivateKey?: ECKey | OKP): any {
        let curve;
        if(this.curves.includes(publicKey.getMinimalJWK().crv)){
            curve = publicKey.getMinimalJWK().crv;
        }
        else{
            throw new Error(ERRORS.UNSUPPORTED_CURVE);
        }

        if(!ephemeralPrivateKey){
            const ec = new EC(curve);
            let keyPair = ec.genKeyPair();

            ephemeralPrivateKey = ECKey.fromKey({
                key: keyPair.getPrivate().toString(16),
                kid: '',
                use: 'enc',
                kty: 'EC',
                format: KEY_FORMATS.HEX,
                isPrivate: true,
            });
        }
    }

    regenerate(privateKey: ECKey | OKP, ephemeralPublicKey: ECKey | OKP): Buffer {
        throw new Error("Method not implemented.");
    }

}