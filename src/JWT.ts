import { Key } from './JWKUtils';
import base64url from 'base64url';
import { createHash } from 'crypto';
import { ec as EC } from 'elliptic';
import { leftpad } from './Utils';
import { ALGORITHMS } from './globals';
const publicKeyToAddress = require('ethereum-public-key-to-address');

interface JWTHeader{
    typ: string,
    alg: string,
    kid: string
}

export interface JWTObject{
    header: JWTHeader,
    payload: object,
}

export interface JWTSignedObject extends JWTObject{
    signed: string,
    signature: Buffer,
}

export const ERRORS = Object.freeze({
    UNSUPPORTED_ALGORITHM: 'Unsupported algorithm',
    INVALID_JWT: 'Invalid JWT',
    INVALID_SIGNATURE: 'Invalid signature',
    ALGORITHM_MISMATCH: 'Key algorithm does not match with JWT algorithm'
});

export function sign(jwtObject: JWTObject, key: Key | string): string {
    let unsigned = base64url.encode(JSON.stringify(jwtObject.header)) + '.' + base64url.encode(JSON.stringify(jwtObject.payload));
    let signature: string | Buffer;

    if(typeof key === 'string'){
        switch (jwtObject.header.alg) {
            case ALGORITHMS[ALGORITHMS["ES256K-R"]]: signature = signES256KRecoverable(unsigned, key); break;
            default: throw new Error(ERRORS.UNSUPPORTED_ALGORITHM);
        }
    }
    else{
        if (jwtObject.header.alg !== key.getAlgorithm()) throw new Error(ERRORS.ALGORITHM_MISMATCH);

        signature = key.sign(unsigned);
    }

    return unsigned + '.' + base64url.encode(signature);
}

export function verify(jwt: string, key: Key| string): boolean{
    let decoded = decodeJWT(jwt);
    if(typeof key === 'string'){
        switch(decoded.header.alg){
            case ALGORITHMS[ALGORITHMS["ES256K-R"]]: return verifyES256KRecoverable(decoded.signed, decoded.signature, key);
            default: throw new Error(ERRORS.UNSUPPORTED_ALGORITHM)
        }
    }
    else {
        if (decoded.header.alg !== key.getAlgorithm()) throw new Error(ERRORS.ALGORITHM_MISMATCH);
        
        return key.verify(decoded.signed, decoded.signature);
    }
}

export function checkKeyPair(privateKey: Key | string, publicKey: Key | string, algorithm: ALGORITHMS): boolean{
    const jwtDecoded: JWTObject = {
        header: {
            alg: ALGORITHMS[algorithm],
            typ: "JWT",
            kid: 'key_1',
        },
        payload: {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
        }
    }

    let jwt = sign(jwtDecoded, privateKey);
    return verify(jwt, publicKey);
}

function signES256KRecoverable(msg: string, privateKey: string,): Buffer{
    let ec = new EC('secp256k1');
    let sha256 = createHash('sha256');

    let hash = sha256.update(msg).digest('hex');

    let signingKey = ec.keyFromPrivate(privateKey);

    let ec256k_signature = signingKey.sign(hash);

    let jose = Buffer.alloc(ec256k_signature.recoveryParam? 65 : 64);
    Buffer.from(leftpad(ec256k_signature.r.toString('hex')), 'hex').copy(jose, 0);
    Buffer.from(leftpad(ec256k_signature.s.toString('hex')), 'hex').copy(jose, 32);
    if (ec256k_signature.recoveryParam) jose[64] = ec256k_signature.recoveryParam;

    return jose;
}

function verifyES256KRecoverable(msg: string, signature: Buffer, publicKey: string): boolean{
    let sha256 = createHash('sha256');
    let ec = new EC('secp256k1');

    let hash = sha256.update(msg).digest();

    if (signature.length !== 65) throw new Error(ERRORS.INVALID_JWT);
    let signatureObj = {
        r: signature.slice(0, 32).toString('hex'),
        s: signature.slice(32, 64).toString('hex'),
    }
    let recoveredKey = ec.recoverPubKey(hash, signatureObj, signature[64]);
    return (
        recoveredKey.encode('hex') === publicKey ||
        recoveredKey.encode('hex', true) === publicKey ||
        publicKeyToAddress(recoveredKey.encode('hex')) === publicKey
    )
}

function decodeJWT(jwt: string): JWTSignedObject{
    try {
        let decodedHeader = JSON.parse(base64url.decode(jwt.split('.')[0]));
        let payload = JSON.parse(base64url.decode(jwt.split('.')[1]));
        let signature = base64url.toBuffer(jwt.split('.')[2]);
        let alg;
        switch(decodedHeader.alg){
            case ALGORITHMS[ALGORITHMS.RS256]: alg = ALGORITHMS[ALGORITHMS.RS256]; break;
            case ALGORITHMS[ALGORITHMS.ES256K]: alg = ALGORITHMS[ALGORITHMS.ES256K]; break;
            case ALGORITHMS[ALGORITHMS["ES256K-R"]]: alg = ALGORITHMS[ALGORITHMS["ES256K-R"]]; break;
            case ALGORITHMS[ALGORITHMS.EdDSA]: alg = ALGORITHMS[ALGORITHMS.EdDSA]; break;
            default: throw new Error(ERRORS.UNSUPPORTED_ALGORITHM);
        }
    
        return {
            header: {
                typ: decodedHeader.typ,
                alg: alg,
                kid: decodedHeader.kid,
            },
            payload,
            signed: jwt.split('.')[0] + '.' + jwt.split('.')[1],
            signature,
        }
    } catch (err) {
        throw new Error(ERRORS.INVALID_JWT);
    }
}