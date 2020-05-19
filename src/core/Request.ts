import { RESOLVER_URL } from './config';
import { Identity, DidDocument } from './Identity';
import * as queryString from 'query-string';
import { ERROR_RESPONSES } from './ErrorResponse';
import base64url from 'base64url';
import { KeySet } from './JWKUtils';
import { ALGORITHMS, KTYS, KEY_FORMATS } from './globals';
import * as JWT from './JWT';
const axios = require('axios').default;

const RESPONSE_TYPES = ['id_token',];
const SUPPORTED_SCOPES = ['openid', 'did_authn',];
const REQUIRED_SCOPES = ['openid', 'did_authn',];

export interface RPInfo{
    redirect_uri: string;
    did: string;
    registration: any;
    did_doc?: DidDocument;
    request_uri?: string;
}

export class DidSiopRequest{
    static async validateRequest(request: string): Promise<JWT.JWTObject>{
        let requestJWT = await validateRequestParams(request);
        let jwtDecoded = await validateRequestJWT(requestJWT);
        return jwtDecoded;
    }

    static async generateRequest(rp: RPInfo, signingInfo: JWT.SigningInfo, options: any): Promise<string> {
        const url = 'openid://';
        const query: any = {
            response_type: 'id_token',
            client_id: rp.redirect_uri,
            scope: 'openid did_authn',
        }

        if (rp.request_uri) {
            query.request_uri = rp.request_uri;
        }
        else {
            let jwtHeader = {
                alg: ALGORITHMS[signingInfo.alg],
                typ: 'JWT',
                kid: signingInfo.kid
            }

            let jwtPayload = {
                iss: rp.did,
                response_type: 'id_token',
                scope: 'openid did_authn',
                client_id: rp.redirect_uri,
                registration: rp.registration,
                ...options
            }

            let jwtObject: JWT.JWTObject = {
                header: jwtHeader,
                payload: jwtPayload
            }

            let jwt = JWT.sign(jwtObject, signingInfo);

            query.request = jwt;
        }

        return queryString.stringifyUrl({
            url,
            query
        });
    }
}

async function validateRequestParams(request: string): Promise<string> {
    let parsed = queryString.parseUrl(request);

    if (
        parsed.url !== 'openid://' ||
        (!parsed.query.client_id || parsed.query.client_id.toString().match(/^ *$/)) ||
        (!parsed.query.response_type || parsed.query.response_type.toString().match(/^ *$/))
    ) return Promise.reject(ERROR_RESPONSES.invalid_request.err);

    if (parsed.query.scope) {
        let requestedScopes = parsed.query.scope.toString().split(' ');
        if (!(requestedScopes.every(s => SUPPORTED_SCOPES.includes(s))) || !(REQUIRED_SCOPES.every(s => requestedScopes.includes(s))))
            return Promise.reject(ERROR_RESPONSES.invalid_scope.err);
    }
    else return Promise.reject(ERROR_RESPONSES.invalid_request.err);

    if (!RESPONSE_TYPES.includes(parsed.query.response_type.toString())) return Promise.reject(ERROR_RESPONSES.unsupported_response_type.err);

    if (parsed.query.request === undefined || parsed.query.request === null) {
        if (parsed.query.request_uri === undefined || parsed.query.request_uri === null) {
            return Promise.reject(ERROR_RESPONSES.invalid_request.err);
        }
        else {
            if (parsed.query.request_uri.toString().match(/^ *$/)) return Promise.reject(ERROR_RESPONSES.invalid_request_uri.err)
            try {
                let returnedValue = await axios.get(parsed.query.request_uri);
                return returnedValue.data ? returnedValue.data : Promise.reject(ERROR_RESPONSES.invalid_request_uri.err);
            } catch (err) {
                return Promise.reject(ERROR_RESPONSES.invalid_request_uri.err);
            }
        }
    }
    else {
        if (parsed.query.request.toString().match(/^ *$/)) return Promise.reject(ERROR_RESPONSES.invalid_request_object.err);
        return parsed.query.request.toString();
    }
}

async function validateRequestJWT(requestJWT: string): Promise<JWT.JWTObject> {
    let decodedHeader;
    let decodedPayload;
    try {
        decodedHeader = JSON.parse(base64url.decode(requestJWT.split('.')[0]));
        decodedPayload = JSON.parse(base64url.decode(requestJWT.split('.')[1]));
    }
    catch (err) {
        return Promise.reject(ERROR_RESPONSES.invalid_request_object.err);
    }

    if (
        (decodedHeader.kid && !decodedHeader.kid.match(/^ *$/)) &&
        (decodedHeader.alg && !decodedHeader.alg.match(/^ *$/)) &&
        (decodedPayload.iss && !decodedPayload.iss.match(/^ *$/)) &&
        (decodedPayload.scope && decodedPayload.scope.indexOf('did_authn') > -1) &&
        (decodedPayload.registration && !JSON.stringify(decodedPayload.registration).match(/^ *$/))
    ) {
        let publicKeyInfo: JWT.SigningInfo | undefined;

        try {
            let identity = new Identity();
            await identity.resolve(decodedPayload.iss);
            
            let didPubKey = identity.getPublicKey(decodedHeader.kid);
            publicKeyInfo = {
                key: didPubKey.keyString,
                kid: didPubKey.id,
                alg: ALGORITHMS[decodedHeader.alg as keyof typeof ALGORITHMS],
                format: didPubKey.format
            }
        } catch (err) {
            try {
                let keyset = new KeySet();
                if(decodedPayload.jwks){
                    keyset.setKeys(decodedPayload.jwks);
                }
                else if(decodedPayload.jwks_uri && decodedPayload.jwks_uri === (RESOLVER_URL + decodedPayload.iss + ';transform-keys=jwks')){
                    keyset.setURI(decodedPayload.jwks_uri);
                }
                let keySetKey = keyset.getKey(decodedPayload.kid)[0];
                let keySetKeyFormat: KEY_FORMATS;
                switch(keySetKey.toJWK().kty){
                    case KTYS[KTYS.RSA]: {
                        keySetKeyFormat = KEY_FORMATS.PKCS1_PEM;
                        break;
                    }
                    case KTYS[KTYS.EC]:
                    case KTYS[KTYS.OKP]: {
                        keySetKeyFormat = KEY_FORMATS.HEX;
                        break;
                    }
                    default: keySetKeyFormat = KEY_FORMATS.HEX;
                }
                publicKeyInfo = {
                    key: keySetKey.exportKey(keySetKeyFormat),
                    kid: keySetKey.toJWK().kid,
                    alg: ALGORITHMS[decodedHeader.alg as keyof typeof ALGORITHMS],
                    format: keySetKeyFormat
                }
            } catch (err) {
                publicKeyInfo = undefined;
            }
        }

        if (publicKeyInfo) {
            let validity = false;

            try {
                validity = JWT.verify(requestJWT, publicKeyInfo);
            } catch (err) {
                return Promise.reject(ERROR_RESPONSES.invalid_request_object.err);
            }

            if (validity) {
                return {
                    header: decodedHeader,
                    payload: decodedPayload
                }
            }
            else {
                return Promise.reject(ERROR_RESPONSES.invalid_request_object.err);
            }
        }
        else {
            return Promise.reject(ERROR_RESPONSES.invalid_request_object.err);
        }
    }
    else {
        return Promise.reject(ERROR_RESPONSES.invalid_request_object.err);
    }
}