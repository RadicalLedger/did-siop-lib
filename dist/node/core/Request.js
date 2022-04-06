"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var config_1 = require("./config");
var Identity_1 = require("./Identity");
var queryString = __importStar(require("query-string"));
var ErrorResponse_1 = require("./ErrorResponse");
var base64url_1 = __importDefault(require("base64url"));
var JWKUtils_1 = require("./JWKUtils");
var globals_1 = require("./globals");
var JWT = __importStar(require("./JWT"));
var axios = require('axios').default;
var RESPONSE_TYPES = ['id_token',];
var SUPPORTED_SCOPES = ['openid', 'did_authn',];
var REQUIRED_SCOPES = ['openid', 'did_authn',];
/**
 * @classdesc This class contains static methods related to DID SIOP request generation and validation
 */
var DidSiopRequest = /** @class */ (function () {
    function DidSiopRequest() {
    }
    /**
     * @param {string} request - A request which needs to be checked for validity
     * @returns {Promise<JWT.JWTObject>} - A Promise which resolves to the decoded request JWT
     * @remarks This method make use of two functions which first validates the url parameters of the request
     * and then the request JWT contained in 'request' or 'requestURI' parameter
     */
    DidSiopRequest.validateRequest = function (request) {
        return __awaiter(this, void 0, void 0, function () {
            var requestJWT, jwtDecoded;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, validateRequestParams(request)];
                    case 1:
                        requestJWT = _a.sent();
                        return [4 /*yield*/, validateRequestJWT(requestJWT)];
                    case 2:
                        jwtDecoded = _a.sent();
                        return [2 /*return*/, jwtDecoded];
                }
            });
        });
    };
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
    DidSiopRequest.generateRequest = function (rp, signingInfo, options) {
        return __awaiter(this, void 0, void 0, function () {
            var url, query, jwtHeader, jwtPayload, jwtObject, jwt;
            return __generator(this, function (_a) {
                url = 'openid://';
                query = {
                    response_type: 'id_token',
                    client_id: rp.redirect_uri,
                    scope: 'openid did_authn',
                };
                if (rp.request_uri) {
                    query.request_uri = rp.request_uri;
                }
                else {
                    jwtHeader = {
                        alg: globals_1.ALGORITHMS[signingInfo.alg],
                        typ: 'JWT',
                        kid: signingInfo.kid
                    };
                    jwtPayload = __assign({ iss: rp.did, response_type: 'id_token', scope: 'openid did_authn', client_id: rp.redirect_uri, registration: rp.registration }, options);
                    jwtObject = {
                        header: jwtHeader,
                        payload: jwtPayload
                    };
                    jwt = JWT.sign(jwtObject, signingInfo);
                    query.request = jwt;
                }
                return [2 /*return*/, queryString.stringifyUrl({
                        url: url,
                        query: query
                    })];
            });
        });
    };
    return DidSiopRequest;
}());
exports.DidSiopRequest = DidSiopRequest;
/**
 * @param {string} request - A DID SIOP request which needs to be validated
 * @returns {string} - An encoded JWT which is extracted from 'request' or 'requestURI' fields
 * @remarks This method is used to check the validity of DID SIOP request URL parameters.
 * If the parameters in the request url is valid then this method returns the encoded request JWT
 * https://identity.foundation/did-siop/#siop-request-validation
 */
function validateRequestParams(request) {
    return __awaiter(this, void 0, void 0, function () {
        var parsed, requestedScopes_1, returnedValue, err_1;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    parsed = queryString.parseUrl(request);
                    if (parsed.url !== 'openid://' ||
                        (!parsed.query.client_id || parsed.query.client_id.toString().match(/^ *$/)) ||
                        (!parsed.query.response_type || parsed.query.response_type.toString().match(/^ *$/)))
                        return [2 /*return*/, Promise.reject(ErrorResponse_1.ERROR_RESPONSES.invalid_request.err)];
                    if (parsed.query.scope) {
                        requestedScopes_1 = parsed.query.scope.toString().split(' ');
                        if (!(requestedScopes_1.every(function (s) { return SUPPORTED_SCOPES.includes(s); })) || !(REQUIRED_SCOPES.every(function (s) { return requestedScopes_1.includes(s); })))
                            return [2 /*return*/, Promise.reject(ErrorResponse_1.ERROR_RESPONSES.invalid_scope.err)];
                    }
                    else
                        return [2 /*return*/, Promise.reject(ErrorResponse_1.ERROR_RESPONSES.invalid_request.err)];
                    if (!RESPONSE_TYPES.includes(parsed.query.response_type.toString()))
                        return [2 /*return*/, Promise.reject(ErrorResponse_1.ERROR_RESPONSES.unsupported_response_type.err)];
                    if (!(parsed.query.request === undefined || parsed.query.request === null)) return [3 /*break*/, 6];
                    if (!(parsed.query.request_uri === undefined || parsed.query.request_uri === null)) return [3 /*break*/, 1];
                    return [2 /*return*/, Promise.reject(ErrorResponse_1.ERROR_RESPONSES.invalid_request.err)];
                case 1:
                    if (parsed.query.request_uri.toString().match(/^ *$/))
                        return [2 /*return*/, Promise.reject(ErrorResponse_1.ERROR_RESPONSES.invalid_request_uri.err)];
                    _a.label = 2;
                case 2:
                    _a.trys.push([2, 4, , 5]);
                    return [4 /*yield*/, axios.get(parsed.query.request_uri)];
                case 3:
                    returnedValue = _a.sent();
                    return [2 /*return*/, returnedValue.data ? returnedValue.data : Promise.reject(ErrorResponse_1.ERROR_RESPONSES.invalid_request_uri.err)];
                case 4:
                    err_1 = _a.sent();
                    return [2 /*return*/, Promise.reject(ErrorResponse_1.ERROR_RESPONSES.invalid_request_uri.err)];
                case 5: return [3 /*break*/, 7];
                case 6:
                    if (parsed.query.request.toString().match(/^ *$/))
                        return [2 /*return*/, Promise.reject(ErrorResponse_1.ERROR_RESPONSES.invalid_request_object.err)];
                    return [2 /*return*/, parsed.query.request.toString()];
                case 7: return [2 /*return*/];
            }
        });
    });
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
function validateRequestJWT(requestJWT) {
    return __awaiter(this, void 0, void 0, function () {
        var decodedHeader, decodedPayload, publicKeyInfo, identity, didPubKey, err_2, keyset, keySetKey, keySetKeyFormat, validity;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    try {
                        decodedHeader = JSON.parse(base64url_1.default.decode(requestJWT.split('.')[0]));
                        decodedPayload = JSON.parse(base64url_1.default.decode(requestJWT.split('.')[1]));
                    }
                    catch (err) {
                        return [2 /*return*/, Promise.reject(ErrorResponse_1.ERROR_RESPONSES.invalid_request_object.err)];
                    }
                    if (!((decodedHeader.kid && !decodedHeader.kid.match(/^ *$/)) &&
                        (decodedHeader.alg && !decodedHeader.alg.match(/^ *$/)) &&
                        (decodedPayload.iss && !decodedPayload.iss.match(/^ *$/)) &&
                        (decodedPayload.scope && decodedPayload.scope.indexOf('did_authn') > -1) &&
                        (decodedPayload.registration && !JSON.stringify(decodedPayload.registration).match(/^ *$/)))) return [3 /*break*/, 5];
                    publicKeyInfo = void 0;
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    identity = new Identity_1.Identity();
                    return [4 /*yield*/, identity.resolve(decodedPayload.iss)];
                case 2:
                    _a.sent();
                    didPubKey = identity.extractAuthenticationKeys().find(function (authKey) { return authKey.id === decodedHeader.kid; });
                    if (didPubKey && globals_1.ALGORITHMS[didPubKey.alg] === decodedHeader.alg) {
                        publicKeyInfo = {
                            key: didPubKey.publicKey,
                            kid: didPubKey.id,
                            alg: didPubKey.alg,
                            format: didPubKey.format
                        };
                    }
                    else {
                        throw new Error(JWKUtils_1.ERRORS.NO_MATCHING_KEY);
                    }
                    return [3 /*break*/, 4];
                case 3:
                    err_2 = _a.sent();
                    try {
                        keyset = new JWKUtils_1.KeySet();
                        if (decodedPayload.jwks) {
                            keyset.setKeys(decodedPayload.jwks);
                        }
                        else if (decodedPayload.jwks_uri && decodedPayload.jwks_uri === (config_1.RESOLVER_URL + decodedPayload.iss + ';transform-keys=jwks')) {
                            keyset.setURI(decodedPayload.jwks_uri);
                        }
                        keySetKey = keyset.getKey(decodedPayload.kid)[0];
                        keySetKeyFormat = void 0;
                        switch (keySetKey.toJWK().kty) {
                            case globals_1.KTYS[globals_1.KTYS.RSA]: {
                                keySetKeyFormat = globals_1.KEY_FORMATS.PKCS1_PEM;
                                break;
                            }
                            case globals_1.KTYS[globals_1.KTYS.EC]:
                            case globals_1.KTYS[globals_1.KTYS.OKP]: {
                                keySetKeyFormat = globals_1.KEY_FORMATS.HEX;
                                break;
                            }
                            default: keySetKeyFormat = globals_1.KEY_FORMATS.HEX;
                        }
                        publicKeyInfo = {
                            key: keySetKey.exportKey(keySetKeyFormat),
                            kid: keySetKey.toJWK().kid,
                            alg: globals_1.ALGORITHMS[decodedHeader.alg],
                            format: keySetKeyFormat
                        };
                    }
                    catch (err) {
                        publicKeyInfo = undefined;
                    }
                    return [3 /*break*/, 4];
                case 4:
                    if (publicKeyInfo) {
                        validity = false;
                        try {
                            validity = JWT.verify(requestJWT, publicKeyInfo);
                        }
                        catch (err) {
                            return [2 /*return*/, Promise.reject(ErrorResponse_1.ERROR_RESPONSES.invalid_request_object.err)];
                        }
                        if (validity) {
                            return [2 /*return*/, {
                                    header: decodedHeader,
                                    payload: decodedPayload
                                }];
                        }
                        else {
                            return [2 /*return*/, Promise.reject(ErrorResponse_1.ERROR_RESPONSES.invalid_request_object.err)];
                        }
                    }
                    else {
                        return [2 /*return*/, Promise.reject(ErrorResponse_1.ERROR_RESPONSES.invalid_request_object.err)];
                    }
                    return [3 /*break*/, 6];
                case 5: return [2 /*return*/, Promise.reject(ErrorResponse_1.ERROR_RESPONSES.invalid_request_object.err)];
                case 6: return [2 /*return*/];
            }
        });
    });
}
//# sourceMappingURL=Request.js.map