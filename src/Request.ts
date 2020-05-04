import { Identity } from './Identity';
import * as urlParser from 'query-string';
import { ERROR_RESPONSES } from './ErrorResponse';
import base64url from 'base64url';
import { Key, KeySet, KeyInputs, RSAKey, ECKey, OKP } from './JWKUtils';
import { ALGORITHMS } from './globals';
import * as JWT from './JWT';
const axios = require('axios').default;

const RESPONSE_TYPES = ['id_token',];
const SUPPORTED_SCOPES = ['openid', 'did_authn',];
const REQUIRED_SCOPES = ['openid', 'did_authn',];

export class DidSiopRequest{
    static async validateRequest(request: string){
        let requestJWT = await validateRequestParams(request);
        let jwtDecoded = await validateRequestJWT(requestJWT);
        return jwtDecoded;
    }
}

async function validateRequestParams(request: string) {
    let parsed = urlParser.parseUrl(request);

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
        return parsed.query.request;
    }
}

async function validateRequestJWT(requestJWT: string) {
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
        (decodedHeader.kid && decodedHeader.kid !== '') &&
        (decodedPayload.iss && decodedPayload.iss !== '') &&
        (decodedPayload.scope && decodedPayload.scope.indexOf('did_authn') > -1) &&
        (decodedPayload.registration && decodedPayload.registration !== '')
    ) {
        let publicKey: Key | string | undefined;

        try {
            let identity = new Identity();
            try{
                identity.setDocument(decodedPayload.did_doc, decodedPayload.iss);
            }
            catch(err){
                await identity.resolve(decodedPayload.iss);
            }

            let didPubKey = identity.getPublicKey(decodedHeader.kid);
            let keyInfo: KeyInputs.KeyInfo = {
                key: didPubKey.keyString,
                kid: didPubKey.id,
                use: 'sig',
                format: didPubKey.format,
                isPrivate: false,
            }

            switch(didPubKey.alg){
                case ALGORITHMS.RS256: publicKey = RSAKey.fromPublicKey(keyInfo); break;
                case ALGORITHMS.ES256K: publicKey = ECKey.fromPublicKey(keyInfo); break;
                case ALGORITHMS.EdDSA: publicKey = OKP.fromPublicKey(keyInfo); break;
                case ALGORITHMS["ES256K-R"]: publicKey = keyInfo.key; break;
            }
        } catch (err) {
            try {
                let keyset = new KeySet();
                if(decodedPayload.jwks){
                    keyset.setKeys(decodedPayload.jwks);
                }
                else if(decodedPayload.jwks_uri){
                    keyset.setURI(decodedPayload.jwks_uri);
                }
                publicKey = keyset.getKey(decodedPayload.kid)[0];
            } catch (err) {
                publicKey = undefined;
            }
        }

        if (publicKey) {
            let validity = false;

            try {
                validity = JWT.verify(requestJWT, publicKey);
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