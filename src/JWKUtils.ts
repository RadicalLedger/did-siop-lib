import { JWK } from 'jose';
import { eddsa as EdDSA, ec as EC } from 'elliptic';
import * as base58 from 'bs58';
import base64url from 'base64url';

export const ERRORS = Object.freeze({
    INVALID_KEY_FORMAT: 'Invalid key format error',
});

export enum KEYFORMATS{
    publicKeyPem,
    publicKeyHex,
    publicKeyBase58,
    publicKeyBase64,
}

export function getOKP(key_str: string, kid: string, keyFormat: KEYFORMATS, isPublic: boolean = true): JWK.OKPKey {
    let key_buffer = Buffer.alloc(1);
    try {
        switch(keyFormat){
            case KEYFORMATS.publicKeyBase58: key_buffer = base58.decode(key_str); break;
            case KEYFORMATS.publicKeyBase64: key_buffer = base64url.toBuffer(base64url.fromBase64(key_str)); break;
            case KEYFORMATS.publicKeyHex: key_buffer = Buffer.from(key_str, 'hex'); break;
            default: throw new Error(ERRORS.INVALID_KEY_FORMAT);
        }
    } catch (err) {
        throw new Error(ERRORS.INVALID_KEY_FORMAT);
    }

    let ed = new EdDSA('ed25519');
    let edKey; 

    try {
        if (isPublic) {
            edKey = ed.keyFromPublic(key_buffer);
            return JWK.asKey({
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": kid,
                "x": base64url.encode(edKey.getPublic()),
                "alg": "EdDSA"
            });
        }
        else{
            edKey = ed.keyFromSecret(key_buffer);
            return JWK.asKey({
                "kty": "OKP",
                "d": base64url.encode(edKey.getSecret()),
                "crv": "Ed25519",
                "kid": kid,
                "x": base64url.encode(edKey.getPublic()),
                "alg": "EdDSA"
            });
        }
    } catch (err) {
        throw new Error(ERRORS.INVALID_KEY_FORMAT);
    }
}

export function getECKey(key_str: string, kid: string, keyFormat: KEYFORMATS, isPublic: boolean = true): JWK.ECKey{
    let key_buffer = Buffer.alloc(1);
    try {
        switch (keyFormat) {
            case KEYFORMATS.publicKeyBase58: key_buffer = base58.decode(key_str); break;
            case KEYFORMATS.publicKeyBase64: key_buffer = base64url.toBuffer(base64url.fromBase64(key_str)); break;
            case KEYFORMATS.publicKeyHex: key_buffer = Buffer.from(key_str, 'hex'); break;
            default: throw new Error(ERRORS.INVALID_KEY_FORMAT);
        }
    } catch (err) {
        throw new Error(ERRORS.INVALID_KEY_FORMAT);
    }

    let ec = new EC('secp256k1');
    let ecKey;

    try {
        if (isPublic) {
            ecKey = ec.keyFromPublic(key_buffer);
            return JWK.asKey({
                "kty": "EC",
                "crv": "secp256k1",
                "kid": kid,
                "x": base64url.encode(ecKey.getPublic().getX().toArrayLike(Buffer)),
                "y": base64url.encode(ecKey.getPublic().getY().toArrayLike(Buffer)),
                "alg": "ES256K"
            });
        }
        else {
            ecKey = ec.keyFromPrivate(key_buffer);
            return JWK.asKey({
                "kty": "EC",
                "d": base64url.encode(ecKey.getPrivate().toArrayLike(Buffer)),
                "crv": "secp256k1",
                "kid": kid,
                "x": base64url.encode(ecKey.getPublic().getX().toArrayLike(Buffer)),
                "y": base64url.encode(ecKey.getPublic().getY().toArrayLike(Buffer)),
                "alg": "ES256K"
            });
        }
    } catch (err) {
        throw new Error(ERRORS.INVALID_KEY_FORMAT);
    }
}