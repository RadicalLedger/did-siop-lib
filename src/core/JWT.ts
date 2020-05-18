import { Key, RSAKey, ECKey, OKP } from './JWKUtils';
import base64url from 'base64url';
import { ALGORITHMS, RSA_ALGORITHMS, EC_ALGORITHMS, OKP_ALGORITHMS, SPECIAL_ALGORITHMS, KEY_FORMATS } from './globals';
import { Signer, RSASigner, ECSigner, OKPSigner, ES256KRecoverableSigner } from './Signers';
import { Verifier, RSAVerifier, ECVerifier, OKPVerifier, ES256KRecoverableVerifier } from './Verifiers';

export interface JWTHeader{
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

export interface SigningInfo{
    alg: ALGORITHMS,
    kid: string,
    key: string,
    format: KEY_FORMATS,
}

export const ERRORS = Object.freeze({
    UNSUPPORTED_ALGORITHM: 'Unsupported algorithm',
    ALGORITHM_MISMATCH: 'Algorithm in jwt header does not match alg in signing info',
    INVALID_JWT: 'Invalid JWT',
    INVALID_SIGNATURE: 'Invalid signature',
});

export function sign(jwtObject: JWTObject, signingInfo: SigningInfo): string {
    let unsigned = base64url.encode(JSON.stringify(jwtObject.header)) + '.' + base64url.encode(JSON.stringify(jwtObject.payload));

    let algorithm: ALGORITHMS = ALGORITHMS[jwtObject.header.alg as keyof typeof ALGORITHMS];
    if(algorithm !== signingInfo.alg) throw new Error(ERRORS.ALGORITHM_MISMATCH);
    let signer: Signer | undefined;
    let key: Key | string | undefined;

    if(RSA_ALGORITHMS.includes(algorithm)){
        signer = new RSASigner();
        key = RSAKey.fromKey({
            key: signingInfo.key,
            kid: signingInfo.kid,
            use: 'sig',
            kty: 'RSA',
            alg: jwtObject.header.alg,
            format: signingInfo.format,
            isPrivate: true,
        });
    }
    else if(EC_ALGORITHMS.includes(algorithm)){
        signer = new ECSigner();
        key = ECKey.fromKey({
            key: signingInfo.key,
            kid: signingInfo.kid,
            use: 'sig',
            kty: 'EC',
            alg: jwtObject.header.alg,
            format: signingInfo.format,
            isPrivate: true,
        });
    }
    else if(OKP_ALGORITHMS.includes(algorithm)){
        signer = new OKPSigner();
        key = OKP.fromKey({
            key: signingInfo.key,
            kid: signingInfo.kid,
            use: 'sig',
            kty: 'OKP',
            alg: jwtObject.header.alg,
            format: signingInfo.format,
            isPrivate: true,
        });
    }
    else if(SPECIAL_ALGORITHMS.includes(algorithm)){
        switch(algorithm){
            case ALGORITHMS["ES256K-R"]: {
                signer = new ES256KRecoverableSigner();
                key = signingInfo.key;
                break;
            }
        }
    }
    
    if(signer && key){
        let signature = signer.sign(unsigned, key, algorithm);
        return unsigned + '.' + base64url.encode(signature);
    }
    else{
        throw new Error(ERRORS.UNSUPPORTED_ALGORITHM);
    }
}

export function verify(jwt: string, signingInfo: SigningInfo): boolean{
    let decoded = decodeJWT(jwt);
    
    let algorithm: ALGORITHMS = ALGORITHMS[decoded.header.alg as keyof typeof ALGORITHMS];
    if(algorithm !== signingInfo.alg) throw new Error(ERRORS.ALGORITHM_MISMATCH);
    let verifier: Verifier | undefined;
    let key: Key| string | undefined;

    if(RSA_ALGORITHMS.includes(algorithm)){
        verifier = new RSAVerifier();
        key = RSAKey.fromKey({
            key: signingInfo.key,
            kid: signingInfo.kid,
            use: 'sig',
            kty: 'RSA',
            alg: decoded.header.alg,
            format: signingInfo.format,
            isPrivate: false,
        });
    }
    else if(EC_ALGORITHMS.includes(algorithm)){
        verifier = new ECVerifier();
        key = ECKey.fromKey({
            key: signingInfo.key,
            kid: signingInfo.kid,
            use: 'sig',
            kty: 'EC',
            alg: decoded.header.alg,
            format: signingInfo.format,
            isPrivate: false,
        });
    }
    else if(OKP_ALGORITHMS.includes(algorithm)){
        verifier = new OKPVerifier();
        key = OKP.fromKey({
            key: signingInfo.key,
            kid: signingInfo.kid,
            use: 'sig',
            kty: 'OKP',
            alg: decoded.header.alg,
            format: signingInfo.format,
            isPrivate: false,
        });
    }
    else if(SPECIAL_ALGORITHMS.includes(algorithm)){
        switch(algorithm){
            case ALGORITHMS["ES256K-R"]: {
                verifier = new ES256KRecoverableVerifier(); 
                key = signingInfo.key;
                break;
            }
        }
    }

    if(verifier && key){
        return verifier.verify(decoded.signed, decoded.signature, key, algorithm);
    }
    else{
        throw new Error(ERRORS.INVALID_SIGNATURE);
    }

}

function decodeJWT(jwt: string): JWTSignedObject{
    try {
        let decodedHeader = JSON.parse(base64url.decode(jwt.split('.')[0]));
        let payload = JSON.parse(base64url.decode(jwt.split('.')[1]));
        let signature = base64url.toBuffer(jwt.split('.')[2]);
    
        return {
            header: {
                typ: decodedHeader.typ,
                alg: decodedHeader.alg,
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