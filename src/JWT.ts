import { JWT, JWK } from 'jose';
import base64url from 'base64url';
import { createHash } from 'crypto';
import { ec as EC } from 'elliptic';
import { leftpad } from './Utils';
const publicKeyToAddress = require('ethereum-public-key-to-address');

export enum ALGORITHMS{
    'RS256',
    'ES256K',
    'ES256K-R',
    'EdDSA',
}

export const ERRORS = Object.freeze({
    UNSUPPORTED_ALGORITHM: 'Unsupported algorithm',
    INVALID_JWT_ES256KRecoverable: 'Invalid JWT for ES256K-R',
    INVALID_SIGNATURE: 'Invalid signature',
});

export function sign(payload: any, kid: string, key: JWK.Key | string, algorithm: ALGORITHMS): string{
    if(typeof key === 'string'){
        switch (algorithm) {
            case ALGORITHMS["ES256K-R"]: return signES256KRecoverable(payload, key, kid);
            default: throw new Error(ERRORS.UNSUPPORTED_ALGORITHM);
        }
    }
    else{
        return JWT.sign(payload, key, { algorithm: ALGORITHMS[algorithm], kid: true });
    }
}

export function verify(jwt: string, key: JWK.Key | string, algorithm: ALGORITHMS): object{
    if(typeof key === 'string'){
        switch(algorithm){
            case ALGORITHMS["ES256K-R"]: return verifyES256KRecoverable(jwt, key);
            default: throw new Error(ERRORS.UNSUPPORTED_ALGORITHM)
        }
    }
    else{
        try {
            return JWT.verify(jwt, key);
        } catch (err) {
            throw new Error(ERRORS.INVALID_SIGNATURE);
        }
    }
}

export function checkKeyPair(privateKey: JWK.Key | string, publicKey: JWK.Key | string, algorithm: ALGORITHMS): boolean{
    const jwtDecoded = {
        header: {
            "alg": "EdDSA",
            "typ": "JWT"
        },
        payload: {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
        }
    }
    const kid = 'key_1'

    try {
        let signature = sign(jwtDecoded.payload, kid, privateKey, algorithm);
        verify(signature, publicKey, algorithm);
        return true;
    } catch (err) {
        return false;
    }
}

function signES256KRecoverable(payload: any, privateKey: string, kid: string): string{
    let ec = new EC('secp256k1');
    let sha256 = createHash('sha256');

    let header = {
        alg: "ES256K-R",
        typ: "JWT",
        kid: kid,
    }

    let unsigned = base64url.encode(JSON.stringify(header)) + '.' + base64url.encode(JSON.stringify(payload));
    let hash = sha256.update(unsigned).digest('hex');

    let signingKey = ec.keyFromPrivate(privateKey);

    let ec256k_signature = signingKey.sign(hash);

    let jose = Buffer.alloc(ec256k_signature.recoveryParam? 65 : 64);
    Buffer.from(leftpad(ec256k_signature.r.toString('hex')), 'hex').copy(jose, 0);
    Buffer.from(leftpad(ec256k_signature.s.toString('hex')), 'hex').copy(jose, 32);
    if (ec256k_signature.recoveryParam) jose[64] = ec256k_signature.recoveryParam;

    return unsigned + '.' + base64url.encode(jose);
}

function verifyES256KRecoverable(jwt: string, publicKey: string): object{
    let sha256 = createHash('sha256');
    let ec = new EC('secp256k1');

    let input = jwt.split('.')[0] + '.' + jwt.split('.')[1];
    let hash = sha256.update(input).digest();

    let sigBuffer = Buffer.from(base64url.toBuffer(jwt.split('.')[2]));
    if (sigBuffer.length !== 65) throw new Error(ERRORS.INVALID_JWT_ES256KRecoverable);
    let signatureObj = {
        r: sigBuffer.slice(0, 32).toString('hex'),
        s: sigBuffer.slice(32, 64).toString('hex')
    }
    let recoveredKey = ec.recoverPubKey(hash, signatureObj, sigBuffer[64]);
    if (
        recoveredKey.encode('hex') === publicKey ||
        recoveredKey.encode('hex', true) === publicKey ||
        publicKeyToAddress(recoveredKey.encode('hex')) === publicKey
    ){
        return JSON.parse(base64url.decode(jwt.split('.')[1]));
    }
    else{
        throw new Error(ERRORS.INVALID_SIGNATURE);
    }
}