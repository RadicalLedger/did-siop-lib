import { RESOLVER_URL } from './config';
import { Identity, DidDocument } from './Identity';
import * as queryString from 'query-string';
import { ERROR_RESPONSES } from './ErrorResponse';
import base64url from 'base64url';
import { KeySet, ERRORS } from './JWKUtils';
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

/**
 * @classdesc This class contains static methods related to DID SIOP request generation and validation
 */
export class DidSiopRequest{
    /**
     * @param {string} request - A request which needs to be checked for validity
     * @returns {Promise<JWT.JWTObject>} - A Promise which resolves to the decoded request JWT
     * @remarks This method make use of two functions which first validates the url parameters of the request 
     * and then the request JWT contained in 'request' or 'requestURI' parameter
     */
    static async validateRequest(request: string): Promise<JWT.JWTObject>{
        let requestJWT = await validateRequestParams(request);
        let jwtDecoded = await validateRequestJWT(requestJWT);
        return jwtDecoded;
    }

    /**
     * @param {RPInfo} rp - Information about the Relying Party (the issuer of the request)
     * @param {JWT.SigningInfo} signingInfo - Information used in the request signing process 
     * @param {any} options - Optional fields. Directly included in the request JWT.
     * Any optional field if not supported will be ignored
     * @returns {Promise<string>} - A Promise which resolves to the request
     * @remarks This method is used to generate a DID SIOP request using information provided by the Relying Party.
     * Process has two steps. First generates the request with URL params 
     * and then creates the signed JWT (unless the 'requestURI' field is specified in RPInfo).
     * JWT is then added to the 'request' param of the request.
     * https://identity.foundation/did-siop/#generate-siop-request
     */
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

/**
 * @param {string} request - A DID SIOP request which needs to be validated
 * @returns {string} - An encoded JWT which is extracted from 'request' or 'requestURI' fields
 * @remarks This method is used to check the validity of DID SIOP request URL parameters.
 * If the parameters in the request url is valid then this method returns the encoded request JWT
 * https://identity.foundation/did-siop/#siop-request-validation
 */
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

/**
 * @param {string} requestJWT - An encoded JWT
 * @returns {Promise<JWT.JWTObject>} - A Promise which resolves to a decoded request JWT
 * @remarks This method is used to verify the authenticity of the request JWT which comes in 'request' or 'requestURI'
 * url parameter of the original request.
 * At first after decoding the JWT, this method checks for mandatory fields and their values.
 * Then it will proceed to verify the signature using a public key retrieved from Relying Party's DID Document.
 * The specific public key used to verify the signature is determined by the 'kid' field in JWT header.
 * If the JWT is successfully verified then this method will return the decoded JWT
 * https://identity.foundation/did-siop/#siop-request-validation
 */
async function validateRequestJWT(requestJWT: string): Promise<JWT.JWTObject> {
    let decodedHeader: JWT.JWTHeader;
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
            
            let didPubKey = identity.extractAuthenticationKeys().find(authKey => { return authKey.id === decodedHeader.kid});
            if(didPubKey && ALGORITHMS[didPubKey.alg] === decodedHeader.alg){
                publicKeyInfo = {
                    key: didPubKey.publicKey,
                    kid: didPubKey.id,
                    alg: didPubKey.alg,
                    format: didPubKey.format
                }
            }else{
                throw new Error(ERRORS.NO_MATCHING_KEY);
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