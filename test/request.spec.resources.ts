import { ALGORITHMS, KEY_FORMATS } from './../src/core/globals';
import { sign } from '../src/core/jwt';
import { getModifiedJWTSigned } from './common.spec.resources';
import {DID_TEST_RESOLVER_DATA_NEW as DIDS } from './did-doc.spec.resources'

let testDidDoc  = DIDS[0].resolverReturn.didDocument;
let testDID     = DIDS[0].did;
let testKeyInfo = DIDS[0].keyInfo;


const jwtGoodDecoded = {
    header: {
        "typ": "JWT",
        "alg": "ES256K",
        "kid": testDidDoc.verificationMethod[1].id,
    },
    payload: {
        "iss": testDID,
        "response_type": "id_token",
        "client_id": "https://my.rp.com/cb",
        "scope": "openid did_authn",
        "state": "af0ifjsldkj",
        "nonce": "n-0S6_WzA2Mj",
        "redirect_uri": 'https://my.rp.com/cb',
        "response_mode": "form_post",
        "registration": {
            "jwks_uri": "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
            "id_token_signed_response_alg": ["ES256K", "EdDSA", "RS256"]
        }
    }
}

const keyPair = {
    privateKey: {
        alg: ALGORITHMS["ES256K"],
        key: testKeyInfo.privateKey,
        kid: testDidDoc.verificationMethod[1].id,
        format: KEY_FORMATS.HEX,
    },
    publicKey: {
        alg: ALGORITHMS["ES256K"],
        key: testKeyInfo.publicKey,
        kid: testDidDoc.verificationMethod[1].id,
        format: KEY_FORMATS.HEX,
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

const jwtGoodEncoded = sign(jwtGoodDecoded, keyPair.privateKey);
const jwt_uri = 'http://localhost/requestJWT';

export const jwts = {
    jwtGoodDecoded,
    jwtGoodEncoded,
    bad: {
        jwtBadNoKid: getModifiedJWTSigned(jwtGoodDecoded,keyPair.privateKey, false, 'kid'),
        jwtBadNoIss: getModifiedJWTSigned(jwtGoodDecoded,keyPair.privateKey, true, 'iss'),
        jwtBadNoScope: getModifiedJWTSigned(jwtGoodDecoded,keyPair.privateKey, true, 'scope'),
        jwtBadIncorrectScope: getModifiedJWTSigned(jwtGoodDecoded,keyPair.privateKey, true, 'scope', 'openid'),
        jwtBadNoRegistration: getModifiedJWTSigned(jwtGoodDecoded,keyPair.privateKey, true, 'registration'),
        jwtBadInvalidClaims: getModifiedJWTSigned(jwtGoodDecoded,keyPair.privateKey, true, 'registration'),
        jwtBadClaimsNoVPToken: getModifiedJWTSigned(jwtGoodDecoded,keyPair.privateKey, true, 'claims',claims.bad),
    },
    good: {
        jwtWithClaims: getModifiedJWTSigned(jwtGoodDecoded,keyPair.privateKey, true, 'claims',claims.good),        
    }
}

export const queryObj = {
    response_type: 'id_token',
    client_id: 'https://rp.example.com/cb',
    scope: 'openid did_authn',
    request: jwtGoodEncoded
}

export const requests = {
    good: {
        requestGoodEmbeddedJWT: 'openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid did_authn&request=' + jwtGoodEncoded,
        requestGoodUriJWT: 'openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid did_authn&request_uri=' + jwt_uri,
        requestGoodWithClaims: 'openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid did_authn&request=' + jwts.good.jwtWithClaims,
    },
    bad: {
        requestBadProtocol: 'opend://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid did_authn&request=' + jwtGoodEncoded,
        requestBadNoSlashes: 'openid:?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid did_authn&request=' + jwtGoodEncoded,
        requestBadNoResponseType: 'openid://?response_tye=id_token&client_id=https://rp.example.com/cb&scope=openid did_authn&request=' + jwtGoodEncoded,
        requestBadIncorrectResponseType: 'openid://?response_type=id_toke&client_id=https://rp.example.com/cb&scope=openid did_authn&request=' + jwtGoodEncoded,
        requestBadNoClientId: 'openid://?response_type=id_token&client_i=https://rp.example.com/cb&scope=openid did_authn&request=' + jwtGoodEncoded,
        requestBadNoScope: 'openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openi did_authn&request=' + jwtGoodEncoded,
        requestBadNoScopeOpenId: 'openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=did_authn&request=' + jwtGoodEncoded,
        requestBadNoScopeDidAuthN: 'openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid&request=' + jwtGoodEncoded,
        requestBadNoJWT: 'openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid did_authn&request=',
        requestBadNoJWTUri: 'openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid did_authn&request_uri=',
        requestBadIncorrectJWTUri: 'openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid did_authn&request_uri=http://localhost/incorrectRequestJWT',
        requestBadJWTNoKid: 'openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid did_authn&request=' + jwts.bad.jwtBadNoKid,
        requestBadJWTNoIss: 'openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid did_authn&request=' + jwts.bad.jwtBadNoIss,
        requestBadJWTNoScope: 'openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid did_authn&request=' + jwts.bad.jwtBadNoScope,
        requestBadJWTIncorrectScope: 'openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid did_authn&request=' + jwts.bad.jwtBadIncorrectScope,
        requestBadJWTNoRegistration: 'openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid did_authn&request=' + jwts.bad.jwtBadNoRegistration,
        requestBadJWTClaimsNoVPToken: 'openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid did_authn&request=' + jwts.bad.jwtBadClaimsNoVPToken,        
    },
    components: {
        signingInfo: {
            alg: ALGORITHMS["ES256K"],
            key: testKeyInfo.privateKey,
            kid: testDidDoc.verificationMethod[1].id,
            format: KEY_FORMATS.HEX,
        },
        rp: {
            did: testDID,
            redirect_uri: 'https://my.rp.com/cb',
            registration: {
                "jwks_uri": "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
                "id_token_signed_response_alg": ["ES256K", "EdDSA", "RS256"]
            }
        },
        options: {
            state: 'af0ifjsldkj',
            nonce: 'n-0S6_WzA2Mj',
            response_mode: "form_post",
        },
        optionsWithClaims: {
            state: 'af0ifjsldkj',
            nonce: 'n-0S6_WzA2Mj',
            response_mode: "form_post",
            claims : claims.good
        }
    }
}