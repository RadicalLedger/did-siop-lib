import { sign } from '../src/core/JWT';
import { JWTObject, SigningInfo } from '../src/core/JWT';

const jwtGoodDecoded = {
    header: {
        "typ": "JWT",
        "alg": "ES256K",
        "kid": "",
    },
    payload: {
        "iss": "",
        "response_type": "id_token",
        "client_id": "https://my.rp.com/cb",
        "scope": "openid did_authn",
        "state": "af0ifjsldkj",
        "nonce": "n-0S6_WzA2Mj",
        "response_mode": "form_post",
        "registration": {
            "jwks_uri": "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
            "id_token_signed_response_alg": ["ES256K", "EdDSA", "RS256"]
        }
    }
}

export const claims ={
    good:{
        "id_token": {
            "email": null
        },
        "vp_token": {
            "presentation_definition": {
                "id": "vp token example",
                "input_descriptors": [
                    {
                        "id": "id card credential",
                        "format": {
                            "ldp_vc": {
                                "proof_type": [
                                    "Ed25519Signature2018"
                                ]
                            }
                        },
                        "constraints": {
                            "fields": [
                                {
                                    "path": [
                                        "$.type"
                                    ],
                                    "filter": {
                                        "type": "string",
                                        "pattern": "IDCardCredential"
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }
    },
    bad:{
        "id_token": {
            "email": null
        },
        "vp_token": {}    
    }
}
export const getModifiedJWT = function (jwt: JWTObject, isPayload: boolean, property: string, value?: any) {    
    let newJWT = JSON.parse(JSON.stringify(jwt));
    if (isPayload) {
        if (value === null) {
            delete newJWT.payload[property];
        }
        else {
            newJWT.payload[property] = value;
        }
    }
    else {
        if (!value) {
            delete newJWT.header[property];
        } else {
            newJWT.header[property] = value;
        }
    }
    return newJWT;
}

export const getModifiedJWTSigned = function (jwt: JWTObject,privateKey:SigningInfo, isPayload: boolean, property: string, value?: any) {
    let newJwt = getModifiedJWT(jwt,isPayload,property,value);
    return sign(newJwt,privateKey);
}
export const getBasicJWT = function(kid:string, iss:string):JWTObject{

    let clonedJWT = JSON.parse(JSON.stringify(jwtGoodDecoded)) //To make a deep copy in an ugly way
    clonedJWT.header["kid"] = kid;
    clonedJWT.header["iss"] = iss;

    return clonedJWT;
}