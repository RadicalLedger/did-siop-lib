import { JWK } from 'jose';
import { eddsa as EdDSA, ec as EC } from 'elliptic';
import * as base58 from 'bs58';
import base64url from 'base64url';
const NodeRSA = require('node-rsa');

export const ERRORS = Object.freeze({
    INVALID_KEY_FORMAT: 'Invalid key format error',
});

export namespace KeyObjects{
    export interface BasicKeyObject{
        kty: string;
        use: 'enc'|'sig';
        kid: string;
        alg: string;
    }

    export interface RSAPrivateKeyObject extends BasicKeyObject{
        p: string;
        q: string;
        d: string;
        e: string;
        qi: string;
        dp: string;
        dq: string;
        n: string;
    }

    export interface RSAPublicKeyObject extends BasicKeyObject{
        e: string;
        n: string;
    }

    export interface ECPrivateKeyObject extends BasicKeyObject{
        crv: string;
        d: string;
        x: string;
        y: string;
    }

    export interface ECPublicKeyObject extends BasicKeyObject {
        crv: string;
        x: string;
        y: string;
    }

    export interface OKPPrivateKeyObject extends BasicKeyObject {
        crv: string;
        d: string;
        x: string;
    }

    export interface OKPPublicKeyObject extends BasicKeyObject {
        crv: string;
        x: string;
    }

    export interface SymmetricKeyObject extends BasicKeyObject {
        k: string;
    }
}

export namespace KeyInputs{
    export enum FORMATS {
        PEM,
        HEX,
        BASE58,
        BASE64,
    }

    interface KeyInfo {
        key: string;
        kid: string;
        use: 'enc' | 'sig';
        format: FORMATS;
    }

    export type RSAPrivateKeyInput = KeyInfo | KeyObjects.RSAPrivateKeyObject;
    export type RSAPublicKeyInput = KeyInfo | KeyObjects.RSAPublicKeyObject;
    export type ECPrivateKeyInput = KeyInfo | KeyObjects.ECPrivateKeyObject;
    export type ECPublicKeyInput = KeyInfo | KeyObjects.ECPublicKeyObject;
    export type OKPPrivateKeyInput = KeyInfo | KeyObjects.OKPPrivateKeyObject;
    export type OKPPublicKeyInput = KeyInfo | KeyObjects.OKPPublicKeyObject;
    export type SymmetricKeyInput = KeyInfo | KeyObjects.SymmetricKeyObject;
}

enum KTYS{
    'RSA',
    'EC',
    'OKP',
    'oct',
}

enum ALGS{
    'RS256',
    'ES256K',
    'EdDSA',
}

export class RSAKey{
    private kty: string;
    private alg: string;
    private kid: string;
    private use: 'enc'|'sig'; 
    private p?: string;
    private q?: string;
    private d?: string;
    private e: string;
    private qi?: string;
    private dp?: string;
    private dq?: string;
    private n: string;
    private private: boolean;

    private constructor(kid: string, kty: KTYS, alg: ALGS, n: string, e: string, use: 'enc'|'sig'){
        this.kid = kid;
        this.kty = KTYS[kty];
        this.alg = ALGS[alg];
        this.use = use;
        this.n = n;
        this.e = e;
        this.private = false;
    }

    static fromPublicKey(keyInput: KeyInputs.RSAPublicKeyInput): RSAKey{
        if('kty' in keyInput){
            return new RSAKey(keyInput.kid, KTYS.RSA, ALGS.RS256, keyInput.n, keyInput.e, keyInput.use);
        }
        else{
            let rsaKey = new NodeRSA();
            let format = keyInput.key.indexOf('-----BEGIN RSA PUBLIC KEY-----') > -1 ? 'pkcs1-public-pem' : 'pkcs8-public-pem';
            rsaKey.importKey(keyInput.key, format);
            let n = base64url.encode(rsaKey.keyPair.n.toBuffer().slice(1));
            let e = rsaKey.keyPair.e.toString(16);
            e = (e % 2 === 0) ? e : '0' + e;
            e = Buffer.from(e, 'hex').toString('base64');
            return new RSAKey(keyInput.kid, KTYS.RSA, ALGS.RS256, n, e, keyInput.use);
        }
    }

    static fromPrivateKey(keyInput: KeyInputs.RSAPrivateKeyInput): RSAKey {
        if ('kty' in keyInput) {
            let rs256Key =  new RSAKey(keyInput.kid, KTYS.RSA, ALGS.RS256, keyInput.n, keyInput.e, keyInput.use);
            rs256Key.private = true;
            rs256Key.p = keyInput.p;
            rs256Key.q = keyInput.q;
            rs256Key.d = keyInput.d;
            rs256Key.qi = keyInput.qi;
            rs256Key.dp = keyInput.dp;
            rs256Key.dq = keyInput.dq;
            return rs256Key;
        }
        else {
            let rsaKey = new NodeRSA();
            let format = keyInput.key.indexOf('-----BEGIN RSA PRIVATE KEY-----') > -1 ? 'pkcs1-private-pem' : 'pkcs8-private-pem';
            rsaKey.importKey(keyInput.key, format);
            let n = base64url.encode(rsaKey.keyPair.n.toBuffer().slice(1));
            let e = rsaKey.keyPair.e.toString(16);
            e = (e % 2 === 0) ? e : '0' + e;
            e = Buffer.from(e, 'hex').toString('base64');

            let rs256Key = new RSAKey(keyInput.kid, KTYS.RSA, ALGS.RS256, n, e, keyInput.use);
            rs256Key.private = true;
            rs256Key.p = base64url.encode(rsaKey.keyPair.p.toBuffer().slice(1));
            rs256Key.q = base64url.encode(rsaKey.keyPair.q.toBuffer().slice(1));
            rs256Key.d = base64url.encode(rsaKey.keyPair.d.toBuffer());
            rs256Key.qi = base64url.encode(rsaKey.keyPair.coeff.toBuffer());
            rs256Key.dp = base64url.encode(rsaKey.keyPair.dmp1.toBuffer());
            rs256Key.dq = base64url.encode(rsaKey.keyPair.dmq1.toBuffer());
            return rs256Key;
        }
    }

    toJWK(): KeyObjects.RSAPrivateKeyObject | KeyObjects.RSAPublicKeyObject{
        if(this.private){
            return {
                kty: this.kty,
                use: this.use,
                kid: this.kid,
                alg: this.alg,
                p: this.p,
                q: this.q,
                d: this.d,
                e: this.e,
                qi: this.qi,
                dp: this.dp,
                dq: this.dq,
                n: this.n,
            }
        }
        else{
            return{
                kty: this.kty,
                use: this.use,
                kid: this.kid,
                alg: this.alg,
                e: this.e,
                n: this.n,
            }
        }
    }

    toPEM(format: 'pkcs8'|'pkcs1' = 'pkcs8'): string {
        let rsaKey = new NodeRSA();
        let exportFormat;
        if(this.private){
            exportFormat = format + '-private-pem';
            rsaKey.importKey({
                n: base64url.toBuffer(this.n + ''),
                e: base64url.toBuffer(this.e + ''),
                p : base64url.toBuffer(this.p + ''),
                q : base64url.toBuffer(this.q + ''),
                d : base64url.toBuffer(this.d + ''),
                coeff : base64url.toBuffer(this.qi + ''),
                dmp1 : base64url.toBuffer(this.dp + ''),
                dmq1 : base64url.toBuffer(this.dq + ''),
            }, 'components');
        }
        else{
            exportFormat = format + '-public-pem'; rsaKey.importKey({
                n: base64url.toBuffer(this.n + ''),
                e: base64url.toBuffer(this.e + ''),
            }, 'components-public');
        }

        return rsaKey.exportKey(exportFormat);
    }

    isPrivate(): boolean{
        return this.private;
    }
}

export function getOKP(key_str: string, kid: string, keyFormat: KeyInputs.FORMATS, isPublic: boolean = true): JWK.OKPKey {
    let key_buffer = Buffer.alloc(1);
    try {
        switch(keyFormat){
            case KeyInputs.FORMATS.BASE58: key_buffer = base58.decode(key_str); break;
            case KeyInputs.FORMATS.BASE64: key_buffer = base64url.toBuffer(base64url.fromBase64(key_str)); break;
            case KeyInputs.FORMATS.HEX: key_buffer = Buffer.from(key_str, 'hex'); break;
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

export function getECKey(key_str: string, kid: string, keyFormat: KeyInputs.FORMATS, isPublic: boolean = true): JWK.ECKey{
    let key_buffer = Buffer.alloc(1);
    try {
        switch (keyFormat) {
            case KeyInputs.FORMATS.BASE58: key_buffer = base58.decode(key_str); break;
            case KeyInputs.FORMATS.BASE64: key_buffer = base64url.toBuffer(base64url.fromBase64(key_str)); break;
            case KeyInputs.FORMATS.HEX: key_buffer = Buffer.from(key_str, 'hex'); break;
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