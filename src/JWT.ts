import { Key } from './JWKUtils';
import base64url from 'base64url';
import { ALGORITHMS, RSA_ALGORITHMS, EC_ALGORITHMS, OKP_ALGORITHMS, SPECIAL_ALGORITHMS } from './globals';
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
    signing_key: Key | string,
}

export const ERRORS = Object.freeze({
    UNSUPPORTED_ALGORITHM: 'Unsupported algorithm',
    INVALID_JWT: 'Invalid JWT',
    INVALID_SIGNATURE: 'Invalid signature',
});

export function sign(jwtObject: JWTObject, key: Key | string): string {
    let unsigned = base64url.encode(JSON.stringify(jwtObject.header)) + '.' + base64url.encode(JSON.stringify(jwtObject.payload));

    let algorithm: ALGORITHMS = ALGORITHMS[jwtObject.header.alg as keyof typeof ALGORITHMS];
    let signer: Signer | undefined = undefined;

    if(RSA_ALGORITHMS.includes(algorithm)){
        signer = new RSASigner();
    }
    else if(EC_ALGORITHMS.includes(algorithm)){
        signer = new ECSigner();
    }
    else if(OKP_ALGORITHMS.includes(algorithm)){
        signer = new OKPSigner();
    }
    else if(SPECIAL_ALGORITHMS.includes(algorithm)){
        switch(algorithm){
            case ALGORITHMS["ES256K-R"]: signer = new ES256KRecoverableSigner(); break;
        }
    }
    
    if(signer){
        let signature = signer.sign(unsigned, key, algorithm);
        return unsigned + '.' + base64url.encode(signature);
    }
    else{
        throw new Error(ERRORS.UNSUPPORTED_ALGORITHM);
    }
}

export function verify(jwt: string, key: Key| string): boolean{
    let decoded = decodeJWT(jwt);
    
    let algorithm: ALGORITHMS = ALGORITHMS[decoded.header.alg as keyof typeof ALGORITHMS];
    let verifier: Verifier | undefined = undefined;

    if(RSA_ALGORITHMS.includes(algorithm)){
        verifier = new RSAVerifier();
    }
    else if(EC_ALGORITHMS.includes(algorithm)){
        verifier = new ECVerifier();
    }
    else if(OKP_ALGORITHMS.includes(algorithm)){
        verifier = new OKPVerifier();
    }
    else if(SPECIAL_ALGORITHMS.includes(algorithm)){
        switch(algorithm){
            case ALGORITHMS["ES256K-R"]: verifier = new ES256KRecoverableVerifier(); break;
        }
    }

    if(verifier){
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