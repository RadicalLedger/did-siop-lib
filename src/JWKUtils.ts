import { eddsa as EdDSA, ec as EC} from 'elliptic';
import * as base58 from 'bs58';
import base64url from 'base64url';
import { createHash, createSign, createVerify, constants as cryptoConstants } from 'crypto';
import { leftpad } from './Utils';
import { KEY_FORMATS, KTYS, ALGORITHMS } from './globals';
const NodeRSA = require('node-rsa');
const axios = require('axios').default;
const publicKeyToAddress = require('ethereum-public-key-to-address');

export const ERRORS = Object.freeze({
    INVALID_KEY_FORMAT: 'Invalid key format error',
    NO_PRIVATE_KEY: 'Not a private key',
    INVALID_SIGNATURE: 'Invalid signature',
    INVALID_KEY: 'Invalid key',
    INVALID_KEY_SET: 'Invalid key in set',
    NO_MATCHING_KEY: 'Matching key cannot be found in key set',
    URI_ERROR: 'Cannot resolve jwks from uri',
    KEY_EXISTS: 'Key already exists in the set',
    INVALID_ALGORITHM: 'Invalid algorithm',
});

export namespace KeyObjects{
    export interface BasicKeyObject{
        kty: string;
        use: string;
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

    export interface KeyInfo {
        key: string;
        kid: string;
        use: string;
        kty: string,
        alg?: string,
        format: KEY_FORMATS;
        isPrivate: boolean;
    }

    export type RSAPrivateKeyInput = KeyInfo | KeyObjects.RSAPrivateKeyObject;
    export type RSAPublicKeyInput = KeyInfo | KeyObjects.RSAPublicKeyObject;
    export type ECPrivateKeyInput = KeyInfo | KeyObjects.ECPrivateKeyObject;
    export type ECPublicKeyInput = KeyInfo | KeyObjects.ECPublicKeyObject;
    export type OKPPrivateKeyInput = KeyInfo | KeyObjects.OKPPrivateKeyObject;
    export type OKPPublicKeyInput = KeyInfo | KeyObjects.OKPPublicKeyObject;
    export type SymmetricKeyInput = KeyInfo | KeyObjects.SymmetricKeyObject;
}

export abstract class Key{
    protected kty: string;
    protected kid: string;
    protected use: string;
    protected alg: string;
    protected private: boolean;

    protected constructor(kid: string, kty: KTYS, use: string, alg?: string){
        this.kid = kid;
        this.kty = KTYS[kty];
        this.use = use;
        this.alg = alg? alg : '';
        this.private = false;
    }

    isPrivate(): boolean{
        return this.private;
    }

    checkKid(kid: string): boolean{
        return this.kid === kid;
    }

    abstract sign(msg: string, algorithm: ALGORITHMS): Buffer;
    abstract verify(msg: string, signature: Buffer, algorithm: ALGORITHMS): boolean;
    abstract toJWK(privateKey: boolean): KeyObjects.BasicKeyObject;
    abstract exportKey(format: KEY_FORMATS): string;
}

export class RSAKey extends Key{
    private p?: string;
    private q?: string;
    private d?: string;
    private e: string;
    private qi?: string;
    private dp?: string;
    private dq?: string;
    private n: string;

    private constructor(kid: string, kty: KTYS, n: string, e: string, use: string, alg?: string){
        super(kid, kty, use, alg);
        this.n = n;
        this.e = e;
    }

    static fromPublicKey(keyInput: KeyInputs.RSAPublicKeyInput): RSAKey{
        if('key' in keyInput){
            let rsaKey = new NodeRSA();
            let format = keyInput.key.indexOf('-----BEGIN RSA PUBLIC KEY-----') > -1 ? 'pkcs1-public-pem' : 'pkcs8-public-pem';
            rsaKey.importKey(keyInput.key, format);
            let n = base64url.encode(rsaKey.keyPair.n.toBuffer().slice(1));
            let e = rsaKey.keyPair.e.toString(16);
            e = (e % 2 === 0) ? e : '0' + e;
            e = Buffer.from(e, 'hex').toString('base64');
            return new RSAKey(keyInput.kid, KTYS.RSA, n, e, keyInput.use, keyInput.alg);
        }
        else{
            return new RSAKey(keyInput.kid, KTYS.RSA, keyInput.n, keyInput.e, keyInput.use, keyInput.alg);
        }
    }

    static fromPrivateKey(keyInput: KeyInputs.RSAPrivateKeyInput): RSAKey {
        if ('key' in keyInput) {
            let rsaKey = new NodeRSA();
            let format = keyInput.key.indexOf('-----BEGIN RSA PRIVATE KEY-----') > -1 ? 'pkcs1-private-pem' : 'pkcs8-private-pem';
            rsaKey.importKey(keyInput.key, format);
            let n = base64url.encode(rsaKey.keyPair.n.toBuffer().slice(1));
            let e = rsaKey.keyPair.e.toString(16);
            e = (e % 2 === 0) ? e : '0' + e;
            e = Buffer.from(e, 'hex').toString('base64');

            let rs256Key = new RSAKey(keyInput.kid, KTYS.RSA, n, e, keyInput.use, keyInput.alg);
            rs256Key.private = true;
            rs256Key.p = base64url.encode(rsaKey.keyPair.p.toBuffer().slice(1));
            rs256Key.q = base64url.encode(rsaKey.keyPair.q.toBuffer().slice(1));
            rs256Key.d = base64url.encode(rsaKey.keyPair.d.toBuffer());
            rs256Key.qi = base64url.encode(rsaKey.keyPair.coeff.toBuffer());
            rs256Key.dp = base64url.encode(rsaKey.keyPair.dmp1.toBuffer());
            rs256Key.dq = base64url.encode(rsaKey.keyPair.dmq1.toBuffer());
            return rs256Key;
        }
        else {
            let rs256Key =  new RSAKey(keyInput.kid, KTYS.RSA, keyInput.n, keyInput.e, keyInput.use, keyInput.alg);
            rs256Key.private = true;
            rs256Key.p = keyInput.p;
            rs256Key.q = keyInput.q;
            rs256Key.d = keyInput.d;
            rs256Key.qi = keyInput.qi;
            rs256Key.dp = keyInput.dp;
            rs256Key.dq = keyInput.dq;
            return rs256Key;
        }
    }

    static fromKey(keyInput: KeyInputs.RSAPublicKeyInput | KeyInputs.RSAPrivateKeyInput): RSAKey {
        if (this.isPrivateKeyInput(keyInput)) return this.fromPrivateKey(keyInput as KeyInputs.RSAPrivateKeyInput);
        return this.fromPublicKey(keyInput as KeyInputs.RSAPublicKeyInput);
    }

    static isPrivateKeyInput(keyInput: KeyInputs.RSAPublicKeyInput | KeyInputs.RSAPrivateKeyInput): boolean {
        if ('key' in keyInput) {
            return keyInput.isPrivate;
        }
        else {
            let privateKeyObject = keyInput as KeyObjects.RSAPrivateKeyObject;
            if (
                privateKeyObject.d &&
                privateKeyObject.dp &&
                privateKeyObject.dq &&
                privateKeyObject.e &&
                privateKeyObject.n &&
                privateKeyObject.p &&
                privateKeyObject.q &&
                privateKeyObject.qi
            ) {
                return true;
            }

            let publicKeyObject = keyInput as KeyObjects.RSAPublicKeyObject;
            if (
                publicKeyObject.e &&
                publicKeyObject.n
            ) {
                return false;
            }

            throw new Error(ERRORS.INVALID_KEY);
        }
    }

    toJWK(privateKey?: boolean): KeyObjects.RSAPrivateKeyObject | KeyObjects.RSAPublicKeyObject{
        if(privateKey){
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
                throw new Error(ERRORS.NO_PRIVATE_KEY);
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

    private toPEM(format: 'pkcs8'|'pkcs1' = 'pkcs8'): string {
        let rsaKey = new NodeRSA();
        let exportFormat;
        if(this.private){
            exportFormat = format + '-private-pem';
            rsaKey.importKey({
                n: base64url.toBuffer(this.n || ' '),
                e: base64url.toBuffer(this.e || ' '),
                p : base64url.toBuffer(this.p || ' '),
                q : base64url.toBuffer(this.q || ' '),
                d : base64url.toBuffer(this.d || ' '),
                coeff : base64url.toBuffer(this.qi || ' '),
                dmp1 : base64url.toBuffer(this.dp || ' '),
                dmq1 : base64url.toBuffer(this.dq || ' '),
            }, 'components');
        }
        else{
            exportFormat = format + '-public-pem'; rsaKey.importKey({
                n: base64url.toBuffer(this.n || ' '),
                e: base64url.toBuffer(this.e || ' '),
            }, 'components-public');
        }

        return rsaKey.exportKey(exportFormat);
    }

    exportKey(format: KEY_FORMATS): string{
        switch(format){
            case KEY_FORMATS.PKCS1_PEM: return this.toPEM('pkcs1');
            case KEY_FORMATS.PKCS8_PEM: return this.toPEM('pkcs8');
            case KEY_FORMATS.HEX:
            case KEY_FORMATS.BASE58:
            case KEY_FORMATS.BASE64:
            case KEY_FORMATS.BASE64URL:
            default: throw new Error(ERRORS.INVALID_KEY_FORMAT);
        }
    }

    sign(msg: string, algorithm: ALGORITHMS): Buffer{
        if(this.private){
            let signer;
            let signerParams: any = {
                key: this.toPEM(),
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
            
            return signer.update(msg).sign(signerParams);
        }
        else{
            throw new Error(ERRORS.NO_PRIVATE_KEY);
        }
    }

    verify(msg: string, signature: Buffer, algorithm: ALGORITHMS): boolean{
        try {
            let verifier;
            let verifierParams: any = {
                key: this.toPEM(),
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

export class ECKey extends Key{
    private crv: string;
    private x: string;
    private y: string;
    private d?: string;

    private constructor(kid: string, kty: KTYS, crv: string, x: string, y: string, use: string, alg?: string){
        super(kid, kty, use, alg);
        this.crv = crv;
        this.x = x;
        this.y = y;
    }

    static fromPublicKey(keyInput: KeyInputs.ECPublicKeyInput): ECKey{
        if('key' in keyInput){
            let key_buffer = Buffer.alloc(1);
            try {
                switch (keyInput.format) {
                    case KEY_FORMATS.BASE58: key_buffer = base58.decode(keyInput.key); break;
                    case KEY_FORMATS.BASE64: key_buffer = base64url.toBuffer(base64url.fromBase64(keyInput.key)); break;
                    case KEY_FORMATS.HEX: key_buffer = Buffer.from(keyInput.key, 'hex'); break;
                    default: throw new Error(ERRORS.INVALID_KEY_FORMAT);
                }
            } catch (err) {
                throw new Error(ERRORS.INVALID_KEY_FORMAT);
            }

            let ec = new EC('secp256k1');
            let ellipticKey;
            ellipticKey = ec.keyFromPublic(key_buffer);
            let x = base64url.encode(ellipticKey.getPublic().getX().toArrayLike(Buffer));
            let y = base64url.encode(ellipticKey.getPublic().getY().toArrayLike(Buffer));
            return new ECKey(keyInput.kid, KTYS.EC, 'secp256k1', x, y, keyInput.use, keyInput.alg);
        }
        else{
            return new ECKey(keyInput.kid, KTYS.EC, keyInput.crv, keyInput.x, keyInput.y, keyInput.use, keyInput.alg);
        }
    }

    static fromPrivateKey(keyInput: KeyInputs.ECPrivateKeyInput): ECKey{
        if ('key' in keyInput) {
            let key_buffer = Buffer.alloc(1);
            try {
                switch (keyInput.format) {
                    case KEY_FORMATS.BASE58: key_buffer = base58.decode(keyInput.key); break;
                    case KEY_FORMATS.BASE64: key_buffer = base64url.toBuffer(base64url.fromBase64(keyInput.key)); break;
                    case KEY_FORMATS.HEX: key_buffer = Buffer.from(keyInput.key, 'hex'); break;
                    default: throw new Error(ERRORS.INVALID_KEY_FORMAT);
                }
            } catch (err) {
                throw new Error(ERRORS.INVALID_KEY_FORMAT);
            }

            let ec = new EC('secp256k1');
            let ellipticKey;
            ellipticKey = ec.keyFromPrivate(key_buffer);
            let x = base64url.encode(ellipticKey.getPublic().getX().toArrayLike(Buffer));
            let y = base64url.encode(ellipticKey.getPublic().getY().toArrayLike(Buffer));
            let ecKey = new ECKey(keyInput.kid, KTYS.EC, 'secp256k1', x, y, keyInput.use, keyInput.alg);
            ecKey.d = base64url.encode(ellipticKey.getPrivate().toArrayLike(Buffer));
            ecKey.private = true;
            return ecKey;
        }
        else {
            let ecKey = new ECKey(keyInput.kid, KTYS.EC, keyInput.crv, keyInput.x, keyInput.y, keyInput.use, keyInput.alg);
            ecKey.private = true;
            ecKey.d = keyInput.d;
            return ecKey;
        }
    }

    static fromKey(keyInput: KeyInputs.ECPublicKeyInput | KeyInputs.ECPrivateKeyInput): ECKey {
        if (this.isPrivateKeyInput(keyInput)) return this.fromPrivateKey(keyInput as KeyInputs.ECPrivateKeyInput);
        return this.fromPublicKey(keyInput as KeyInputs.ECPublicKeyInput);
    }

    static isPrivateKeyInput(keyInput: KeyInputs.ECPublicKeyInput | KeyInputs.ECPrivateKeyInput): boolean {
        if ('key' in keyInput) {
            return keyInput.isPrivate;
        }
        else {
            let privateKeyObject = keyInput as KeyObjects.ECPrivateKeyObject;
            if (
                privateKeyObject.d &&
                privateKeyObject.x &&
                privateKeyObject.y
            ) {
                return true;
            }

            let publicKeyObject = keyInput as KeyObjects.ECPublicKeyObject;
            if (
                publicKeyObject.x &&
                publicKeyObject.y
            ) {
                return false;
            }

            throw new Error(ERRORS.INVALID_KEY);
        }
    }

    toJWK(privateKey?: boolean): KeyObjects.ECPrivateKeyObject | KeyObjects.ECPublicKeyObject{
        if(privateKey){
            if (this.private) {
                return {
                    kty: this.kty,
                    use: this.use,
                    kid: this.kid,
                    alg: this.alg,
                    crv: this.crv,
                    x: this.x,
                    y: this.y,
                    d: this.d,
                }
            }
            else{
                throw new Error(ERRORS.NO_PRIVATE_KEY);
            }
        }
        else {
            return {
                kty: this.kty,
                use: this.use,
                kid: this.kid,
                alg: this.alg,
                crv: this.crv,
                x: this.x,
                y: this.y,
            }
        }
    }

    exportKey(format: KEY_FORMATS): string {
        let ec = new EC('secp256k1');
        let keyString: Buffer;
        if (this.private) {
            keyString = ec.keyFromPrivate(base64url.toBuffer(this.d || ' ')).getPrivate().toArrayLike(Buffer);
        }
        else {
            let pub = {
                x: base64url.decode(this.x, 'hex'),
                y: base64url.decode(this.y, 'hex')
            }
            keyString = Buffer.from(ec.keyFromPublic(pub).getPublic().encode('hex', false), 'hex');
        }

        switch (format) {
            case KEY_FORMATS.HEX: return keyString.toString('hex');
            case KEY_FORMATS.BASE58: return base58.encode(keyString);
            case KEY_FORMATS.BASE64: return keyString.toString('base64');
            case KEY_FORMATS.BASE64URL: return base64url.encode(keyString);
            case KEY_FORMATS.PKCS1_PEM:
            case KEY_FORMATS.PKCS8_PEM: 
            default: throw new Error(ERRORS.INVALID_KEY_FORMAT);
        }
    }

    sign(msg: string, algorithm: ALGORITHMS): Buffer{
        if(this,this.private){
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
                case ALGORITHMS["ES256K-R"]:{
                    sha = createHash('sha256'); 
                    ec = new EC('secp256k1'); 

                    let hash = sha.update(msg).digest('hex');

                    let signingKey = ec.keyFromPrivate(this.exportKey(KEY_FORMATS.HEX));

                    let ec256k_signature = signingKey.sign(hash);

                    let jose = Buffer.alloc(ec256k_signature.recoveryParam? 65 : 64);
                    Buffer.from(leftpad(ec256k_signature.r.toString('hex')), 'hex').copy(jose, 0);
                    Buffer.from(leftpad(ec256k_signature.s.toString('hex')), 'hex').copy(jose, 32);
                    if (ec256k_signature.recoveryParam) jose[64] = ec256k_signature.recoveryParam;

                    return jose;
                }
                default: throw new Error(ERRORS.INVALID_ALGORITHM);
            }

            let hash = sha.update(msg).digest('hex');

            let key = ec.keyFromPrivate(this.exportKey(KEY_FORMATS.HEX));

            let ec256k_signature = key.sign(hash);

            let signature = Buffer.alloc(64);
            Buffer.from(leftpad(ec256k_signature.r.toString('hex')), 'hex').copy(signature, 0);
            Buffer.from(leftpad(ec256k_signature.s.toString('hex')), 'hex').copy(signature, 32);

            return signature;
        }
        else{
            throw new Error(ERRORS.NO_PRIVATE_KEY);
        }
    }

    verify(msg: string, signature: Buffer, algorithm: ALGORITHMS, publicKeyAddress?: string): boolean{
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
                case ALGORITHMS["ES256K-R"]:{
                    sha = createHash('sha256'); 
                    ec = new EC('secp256k1'); 

                    let hash = sha.update(msg).digest();

                    if (signature.length !== 65) throw new Error(ERRORS.INVALID_SIGNATURE);
                    let signatureObj = {
                        r: signature.slice(0, 32).toString('hex'),
                        s: signature.slice(32, 64).toString('hex'),
                    }
                    let recoveredKey = ec.recoverPubKey(hash, signatureObj, signature[64]);
                    return (
                        recoveredKey.encode('hex') === publicKeyAddress ||
                        recoveredKey.encode('hex', true) === publicKeyAddress ||
                        publicKeyToAddress(recoveredKey.encode('hex')) === publicKeyAddress
                    )
                }
                default: throw new Error(ERRORS.INVALID_ALGORITHM);
            }

    
            let hash = sha.update(msg).digest();
    
            if (signature.length !== 64) throw new Error(ERRORS.INVALID_SIGNATURE);
            let signatureObj = {
                r: signature.slice(0, 32).toString('hex'),
                s: signature.slice(32, 64).toString('hex')
            }
    
            let key = ec.keyFromPublic(this.exportKey(KEY_FORMATS.HEX), 'hex');
    
            return key.verify(hash, signatureObj);
        } catch (err) {
            throw new Error(ERRORS.INVALID_SIGNATURE);
        }
    }
}

export class OKP extends Key{
    private crv: string;
    private x: string;
    private d?: string;

    private constructor(kid: string, kty: KTYS, crv: string, x: string, use: string, alg?: string) {
        super(kid, kty, use, alg);
        this.crv = crv;
        this.x = x;
    }

    static fromPublicKey(keyInput: KeyInputs.OKPPublicKeyInput): OKP {
        if ('key' in keyInput) {
            let key_buffer = Buffer.alloc(1);
            try {
                switch (keyInput.format) {
                    case KEY_FORMATS.BASE58: key_buffer = base58.decode(keyInput.key); break;
                    case KEY_FORMATS.BASE64: key_buffer = base64url.toBuffer(base64url.fromBase64(keyInput.key)); break;
                    case KEY_FORMATS.HEX: key_buffer = Buffer.from(keyInput.key, 'hex'); break;
                    default: throw new Error(ERRORS.INVALID_KEY_FORMAT);
                }
            } catch (err) {
                throw new Error(ERRORS.INVALID_KEY_FORMAT);
            }

            let ed = new EdDSA('ed25519');
            let ellipticKey;
            ellipticKey = ed.keyFromPublic(key_buffer);
            let x = base64url.encode(ellipticKey.getPublic());
            return new OKP(keyInput.kid, KTYS.OKP, 'Ed25519', x, keyInput.use, keyInput.alg);
        }
        else {
            return new OKP(keyInput.kid, KTYS.OKP, keyInput.crv, keyInput.x, keyInput.use, keyInput.alg);
        }
    }

    static fromPrivateKey(keyInput: KeyInputs.OKPPrivateKeyInput): OKP {
        if ('key' in keyInput) {
            let key_buffer = Buffer.alloc(1);
            try {
                switch (keyInput.format) {
                    case KEY_FORMATS.BASE58: key_buffer = base58.decode(keyInput.key); break;
                    case KEY_FORMATS.BASE64: key_buffer = base64url.toBuffer(base64url.fromBase64(keyInput.key)); break;
                    case KEY_FORMATS.HEX: key_buffer = Buffer.from(keyInput.key, 'hex'); break;
                    default: throw new Error(ERRORS.INVALID_KEY_FORMAT);
                }
            } catch (err) {
                throw new Error(ERRORS.INVALID_KEY_FORMAT);
            }

            let ed = new EdDSA('ed25519');
            let ellipticKey;
            ellipticKey = ed.keyFromSecret(key_buffer);
            let x = base64url.encode(ellipticKey.getPublic());
            let ecKey = new OKP(keyInput.kid, KTYS.OKP, 'Ed25519', x, keyInput.use, keyInput.alg);
            ecKey.d = base64url.encode(ellipticKey.getSecret());
            ecKey.private = true;
            return ecKey;
        }
        else {
            let ecKey = new OKP(keyInput.kid, KTYS.OKP, keyInput.crv, keyInput.x, keyInput.use, keyInput.alg);
            ecKey.private = true;
            ecKey.d = keyInput.d;
            return ecKey;
        }
    }

    static fromKey(keyInput: KeyInputs.OKPPublicKeyInput | KeyInputs.OKPPrivateKeyInput): OKP {
        if (this.isPrivateKeyInput(keyInput)) return this.fromPrivateKey(keyInput as KeyInputs.OKPPrivateKeyInput);
        return this.fromPublicKey(keyInput as KeyInputs.OKPPublicKeyInput);
    }

    static isPrivateKeyInput(keyInput: KeyInputs.OKPPublicKeyInput | KeyInputs.OKPPrivateKeyInput): boolean {
        if ('key' in keyInput) {
            return keyInput.isPrivate;
        }
        else {
            let privateKeyObject = keyInput as KeyObjects.OKPPrivateKeyObject;
            if (
                privateKeyObject.d &&
                privateKeyObject.x 
            ) {
                return true;
            }

            let publicKeyObject = keyInput as KeyObjects.OKPPublicKeyObject;
            if (
                publicKeyObject.x
            ) {
                return false;
            }

            throw new Error(ERRORS.INVALID_KEY);
        }
    }

    toJWK(privateKey?: boolean): KeyObjects.OKPPrivateKeyObject | KeyObjects.OKPPublicKeyObject {
        if(privateKey){
            if (this.private) {
                return {
                    kty: this.kty,
                    use: this.use,
                    kid: this.kid,
                    alg: this.alg,
                    crv: this.crv,
                    x: this.x,
                    d: this.d,
                }
            }
            else{
                throw new Error(ERRORS.NO_PRIVATE_KEY);
            }
        }
        else {
            return {
                kty: this.kty,
                use: this.use,
                kid: this.kid,
                alg: this.alg,
                crv: this.crv,
                x: this.x,
            }
        }
    }

    exportKey(format: KEY_FORMATS): string {
        let ed = new EdDSA('ed25519');
        let keyString: Buffer;
        if (this.private) {
            keyString = ed.keyFromSecret(base64url.toBuffer(this.d || ' ')).getSecret();
        }
        else {
            keyString = ed.keyFromPublic(base64url.toBuffer(this.x)).getPublic();
        }

        switch (format) {
            case KEY_FORMATS.HEX: return keyString.toString('hex');
            case KEY_FORMATS.BASE58: return base58.encode(keyString);
            case KEY_FORMATS.BASE64: return keyString.toString('base64');
            case KEY_FORMATS.BASE64URL: return base64url.encode(keyString);
            case KEY_FORMATS.PKCS1_PEM:
            case KEY_FORMATS.PKCS8_PEM:
            default: throw new Error(ERRORS.INVALID_KEY_FORMAT);
        }
    }

    sign(msg: string, algorithm: ALGORITHMS): Buffer{
        if(this.private){
            let ed;

            switch(algorithm){
                case ALGORITHMS.EdDSA: {
                    ed = new EdDSA('ed25519'); 
                    break;
                }
                default: throw new Error(ERRORS.INVALID_ALGORITHM);
            }

            let key = ed.keyFromSecret(this.exportKey(KEY_FORMATS.HEX));

            let edDsa_signature = key.sign(Buffer.from(msg));
            return Buffer.from(edDsa_signature.toHex(), 'hex');
        }
        else{
            throw new Error(ERRORS.NO_PRIVATE_KEY);
        }
    }

    verify(msg: string, signature: Buffer, algorithm: ALGORITHMS): boolean{
        try {
            let ed;

            switch(algorithm){
                case ALGORITHMS.EdDSA: {
                    ed = new EdDSA('ed25519'); 
                    break;
                }
                default: throw new Error(ERRORS.INVALID_ALGORITHM);
            }
    
            let key = ed.keyFromPublic(this.exportKey(KEY_FORMATS.HEX));
    
            return key.verify(Buffer.from(msg), signature.toString('hex'));
        } catch (err) {
            throw new Error(ERRORS.INVALID_SIGNATURE);
        }
    }
}

export class KeySet{
    private ketSet: Key[] = [];
    private uri: string = '';

    setKeys(keySet: KeyObjects.BasicKeyObject[]){
        let newKeySet: Key[] = [];
        keySet.forEach(key =>{
            switch(key.kty){
                case KTYS[KTYS.RSA]: {
                    newKeySet.push(RSAKey.fromKey(key as KeyObjects.RSAPrivateKeyObject | KeyObjects.RSAPublicKeyObject));
                    break;
                }
                case KTYS[KTYS.EC]: {
                    newKeySet.push(ECKey.fromKey(key as KeyObjects.ECPrivateKeyObject | KeyObjects.ECPublicKeyObject));
                    break;
                }
                case KTYS[KTYS.OKP]: {
                    newKeySet.push(OKP.fromKey(key as KeyObjects.OKPPrivateKeyObject | KeyObjects.OKPPublicKeyObject));
                    break;
                }
                default: throw new Error(ERRORS.INVALID_KEY_SET);
            }
        });
        this.ketSet = newKeySet;
    }

    async setURI(uri: string){
        this.uri = uri;
        try{
            let returnedSet = await axios.get(this.uri);
            this.setKeys(returnedSet.data.keys);
        }
        catch(err){
            throw new Error(ERRORS.URI_ERROR);
        }
    }

    getKey(kid: string): Key[]{
        let keys = this.ketSet.filter(k => {return k.checkKid(kid)});
        if(keys.length > 0) return keys;
        throw new Error(ERRORS.NO_MATCHING_KEY);
    }

    addKey(key: KeyObjects.BasicKeyObject){
        if(this.ketSet.filter(k => {return k.checkKid(key.kid)}).length === 0){
            switch (key.kty) {
                case KTYS[KTYS.RSA]: {
                    this.ketSet.push(RSAKey.fromKey(key as KeyObjects.RSAPrivateKeyObject | KeyObjects.RSAPublicKeyObject));
                    break;
                }
                case KTYS[KTYS.EC]: {
                    this.ketSet.push(ECKey.fromKey(key as KeyObjects.ECPrivateKeyObject | KeyObjects.ECPublicKeyObject));
                    break;
                }
                case KTYS[KTYS.OKP]: {
                    this.ketSet.push(OKP.fromKey(key as KeyObjects.OKPPrivateKeyObject | KeyObjects.OKPPublicKeyObject));
                    break;
                }
                default: throw new Error(ERRORS.INVALID_KEY_SET);
            }
        }
        else{
            throw new Error(ERRORS.KEY_EXISTS);
        }
    }

    removeKey(kid: string){
        this.ketSet = this.ketSet.filter(key => {return !key.checkKid(kid)});
    }

    size(): number{
        return this.ketSet.length;
    }
}