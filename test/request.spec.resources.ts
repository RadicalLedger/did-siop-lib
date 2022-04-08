import { ALGORITHMS, KEY_FORMATS } from './../src/core/globals';
import { JWTObject } from './../src/core/JWT';
import { sign } from '../src/core/JWT';
import {DID_TEST_RESOLVER_DATA_NEW as DIDS } from './did_doc.spec.resources'

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

const jwtGoodEncoded = sign(jwtGoodDecoded, keyPair.privateKey);
const jwt_uri = 'http://localhost/requestJWT';

const getBadRequestJWT = function (jwt: JWTObject, isPayload: boolean, property: string, value?: string) {
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
    return sign(newJWT, keyPair.privateKey);
}

export const jwts = {
    jwtGoodDecoded,
    jwtGoodEncoded,
    bad: {
        jwtBadNoKid: getBadRequestJWT(jwtGoodDecoded, false, 'kid'),
        jwtBadNoIss: getBadRequestJWT(jwtGoodDecoded, true, 'iss'),
        jwtBadNoScope: getBadRequestJWT(jwtGoodDecoded, true, 'scope'),
        jwtBadIncorrectScope: getBadRequestJWT(jwtGoodDecoded, true, 'scope', 'openid'),
        jwtBadNoRegistration: getBadRequestJWT(jwtGoodDecoded, true, 'registration'),
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
        requestGoodUriJWT: 'openid://?response_type=id_token&client_id=https://rp.example.com/cb&scope=openid did_authn&request_uri=' + jwt_uri
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
        }
    }
}