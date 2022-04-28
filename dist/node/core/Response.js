"use strict";
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
var globals_1 = require("./globals");
var JWT = __importStar(require("./JWT"));
var Identity_1 = require("./Identity");
var JWKUtils_1 = require("./JWKUtils");
var base64url_1 = __importDefault(require("base64url"));
var ErrorResponse = __importStar(require("./ErrorResponse"));
var Claims_1 = require("./Claims");
var ErrorResponse_1 = require("./ErrorResponse");
var ERRORS = Object.freeze({
    UNSUPPORTED_ALGO: 'Algorithm not supported',
    PUBLIC_KEY_ERROR: 'Cannot resolve public key',
    KEY_MISMATCH: 'Signing key does not match kid',
    MALFORMED_JWT_ERROR: 'Malformed response jwt',
    NON_SIOP_FLOW: 'Response jwt is not compatible with SIOP flow',
    INCORRECT_AUDIENCE: 'Incorrect audience',
    INCORRECT_NONCE: 'Incorrect nonce',
    NO_ISSUED_TIME: 'No iat in jwt',
    NO_EXPIRATION: 'No exp in jwt',
    JWT_VALIDITY_EXPIRED: 'JWT validity has expired',
    INVALID_JWK_THUMBPRINT: 'Invalid sub (sub_jwk thumbprint)',
    INVALID_SIGNATURE_ERROR: 'Invalid signature error',
});
/**
 * @classdesc This class contains static methods related to DID SIOP response generation and validation
 */
var DidSiopResponse = /** @class */ (function () {
    function DidSiopResponse() {
    }
    /**
     * @param {any} requestPayload - Payload of the request JWT. Some information from this object is needed in constructing the response
     * @param {JWT.SigningInfo} signingInfo - Key information used to sign the response JWT
     * @param {Identity} didSiopUser - Used to retrieve the information about the provider (user DID) which are included in the response
     * @param {number} [expiresIn = 1000] - Amount of time under which generated id_token (response) is valid. The party which validate the
     * response can either consider this value or ignore it
     * @returns {Promise<string>} - A promise which resolves to a response (id_token) (JWT)
     * @remarks This method first checks if given SigningInfo is compatible with the algorithm required by the RP in
     * 'requestPayload.registration.id_token_signed_response_alg' field.
     * Then it proceeds to extract provider's (user) public key from 'didSiopUser' param using 'kid' field in 'signingInfo' param.
     * Finally it will create the response JWT (id_token) with relevant information, sign it using 'signingInfo' and return it.
     * https://identity.foundation/did-siop/#generate-siop-response
     */
    DidSiopResponse.generateResponse = function (requestPayload, signingInfo, didSiopUser, expiresIn, vps) {
        if (expiresIn === void 0) { expiresIn = 1000; }
        return __awaiter(this, void 0, void 0, function () {
            var header, alg, keys, didPubKey, publicKey, keyInfo, payload, err_1, unsigned, err_2;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 7, , 8]);
                        header = void 0;
                        alg = '';
                        if (requestPayload.registration.id_token_signed_response_alg.includes(globals_1.ALGORITHMS[signingInfo.alg])) {
                            alg = globals_1.ALGORITHMS[signingInfo.alg];
                        }
                        else {
                            Promise.reject(ERRORS.UNSUPPORTED_ALGO);
                        }
                        keys = didSiopUser.extractAuthenticationKeys();
                        didPubKey = keys.find(function (authKey) { return authKey.id === signingInfo.kid; });
                        header = {
                            typ: 'JWT',
                            alg: alg,
                            kid: signingInfo.kid,
                        };
                        publicKey = void 0;
                        keyInfo = void 0;
                        if (didPubKey) {
                            keyInfo = {
                                key: didPubKey.publicKey,
                                kid: didPubKey.id,
                                use: 'sig',
                                kty: globals_1.KTYS[didPubKey.kty],
                                format: didPubKey.format,
                                isPrivate: false,
                            };
                            switch (didPubKey.kty) {
                                case globals_1.KTYS.RSA:
                                    publicKey = JWKUtils_1.RSAKey.fromKey(keyInfo);
                                    break;
                                case globals_1.KTYS.EC: {
                                    if (didPubKey.format === globals_1.KEY_FORMATS.ETHEREUM_ADDRESS) {
                                        keyInfo.key = signingInfo.key;
                                        keyInfo.format = signingInfo.format;
                                        keyInfo.isPrivate = true;
                                    }
                                    publicKey = JWKUtils_1.ECKey.fromKey(keyInfo);
                                    break;
                                }
                                case globals_1.KTYS.OKP:
                                    publicKey = JWKUtils_1.OKP.fromKey(keyInfo);
                                    break;
                            }
                        }
                        else {
                            return [2 /*return*/, Promise.reject(new Error(ERRORS.PUBLIC_KEY_ERROR))];
                        }
                        payload = {
                            iss: 'https://self-issued.me',
                        };
                        payload.did = didSiopUser.getDocument().id;
                        if (requestPayload.client_id)
                            payload.aud = requestPayload.client_id;
                        if (publicKey) {
                            payload.sub_jwk = publicKey.getMinimalJWK();
                            payload.sub = JWKUtils_1.calculateThumbprint(publicKey.getMinimalJWK());
                        }
                        else {
                            return [2 /*return*/, Promise.reject(new Error(ERRORS.PUBLIC_KEY_ERROR))];
                        }
                        if (requestPayload.nonce)
                            payload.nonce = requestPayload.nonce;
                        if (requestPayload.state)
                            payload.state = requestPayload.state;
                        payload.iat = Date.now();
                        payload.exp = Date.now() + expiresIn;
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 5, , 6]);
                        return [4 /*yield*/, Claims_1.validateRequestJWTClaims(requestPayload)];
                    case 2:
                        _a.sent();
                        if (!(vps && vps._vp_token)) return [3 /*break*/, 4];
                        return [4 /*yield*/, Claims_1.validateResponse_VPToken(vps._vp_token)];
                    case 3:
                        _a.sent();
                        payload._vp_token = vps._vp_token;
                        _a.label = 4;
                    case 4: return [3 /*break*/, 6];
                    case 5:
                        err_1 = _a.sent();
                        return [2 /*return*/, Promise.reject(ErrorResponse_1.ERROR_RESPONSES.vp_token_missing_presentation_definition.response.error)];
                    case 6:
                        unsigned = {
                            header: header,
                            payload: payload,
                        };
                        return [2 /*return*/, JWT.sign(unsigned, signingInfo)];
                    case 7:
                        err_2 = _a.sent();
                        return [2 /*return*/, Promise.reject(err_2)];
                    case 8: return [2 /*return*/];
                }
            });
        });
    };
    /**
     * @param {any} requestPayload - Payload of the request JWT. Some information from this object is needed in constructing the header of JWT & keys for signing
     * @param {JWT.SigningInfo} signingInfo - Key information used to sign the response JWT
     * @param {Identity} didSiopUser - Used to retrieve the information about the provider (user DID) which are included in the response
     * response can either consider this value or ignore it
     * @returns {Promise<string>} - A promise which resolves to a response (id_token) (JWT)
     * @remarks This method first checks if given SigningInfo is compatible with the algorithm required by the RP in
     * 'requestPayload.registration.id_token_signed_response_alg' field.
     * Then it proceeds to extract provider's (user) public key from 'didSiopUser' param using 'kid' field in 'signingInfo' param.
     * Finally it will create the response JWT (id_token) with relevant information, sign it using 'signingInfo' and return it.
     * https://identity.foundation/did-siop/#generate-siop-response
     */
    DidSiopResponse.generateResponseVPToken = function (requestPayload, signingInfo, vps) {
        return __awaiter(this, void 0, void 0, function () {
            var header, alg, payload, err_3, unsigned, err_4;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 6, , 7]);
                        header = void 0;
                        alg = '';
                        if (requestPayload.registration.id_token_signed_response_alg.includes(globals_1.ALGORITHMS[signingInfo.alg])) {
                            alg = globals_1.ALGORITHMS[signingInfo.alg];
                        }
                        else {
                            Promise.reject(ERRORS.UNSUPPORTED_ALGO);
                        }
                        header = {
                            typ: 'JWT',
                            alg: alg,
                            kid: signingInfo.kid,
                        };
                        payload = null;
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 4, , 5]);
                        if (!(vps && vps.vp_token)) return [3 /*break*/, 3];
                        return [4 /*yield*/, Claims_1.validateResponseVPToken(vps.vp_token)];
                    case 2:
                        _a.sent();
                        payload = vps.vp_token;
                        _a.label = 3;
                    case 3: return [3 /*break*/, 5];
                    case 4:
                        err_3 = _a.sent();
                        return [2 /*return*/, Promise.reject(ErrorResponse_1.ERROR_RESPONSES.vp_token_missing_presentation_definition.err)];
                    case 5:
                        unsigned = {
                            header: header,
                            payload: payload,
                        };
                        return [2 /*return*/, JWT.sign(unsigned, signingInfo)];
                    case 6:
                        err_4 = _a.sent();
                        return [2 /*return*/, Promise.reject(err_4)];
                    case 7: return [2 /*return*/];
                }
            });
        });
    };
    /**
     * @param {any} requestPayload - Payload of the request JWT. Some information from this object is needed in constructing the response
     * @param {JWT.SigningInfo} signingInfo - Key information used to sign the response JWT
     * @param {Identity} didSiopUser - Used to retrieve the information about the provider (user DID) which are included in the response
     * @param {number} [expiresIn = 1000] - Amount of time under which generated id_token (response) is valid. The party which validate the
     * @param {vps} VPData - This contains the data for vp_token and additional info to send via id_token (_vp_token)
     * @returns {Promise<any>} - A promise which resolves to a JSON object with id_token and vp_token as signed strings
     * @remarks This method geenrate id_token and vp_token needed in an authentication response
     * https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0.html#name-response
     */
    DidSiopResponse.generateResponseWithVPData = function (requestPayload, signingInfo, didSiopUser, expiresIn, vps) {
        if (expiresIn === void 0) { expiresIn = 1000; }
        return __awaiter(this, void 0, void 0, function () {
            var id_token_s, vp_token_s, tokens, err_5;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        id_token_s = "";
                        vp_token_s = "";
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 6, , 7]);
                        return [4 /*yield*/, this.generateResponse(requestPayload, signingInfo, didSiopUser, expiresIn, vps._vp_token)]; // Generate ID Token
                    case 2:
                        id_token_s = _a.sent(); // Generate ID Token
                        if (!(vps && vps.vp_token)) return [3 /*break*/, 5];
                        return [4 /*yield*/, Claims_1.validateResponseVPToken(vps.vp_token)];
                    case 3:
                        _a.sent();
                        return [4 /*yield*/, this.generateResponseVPToken(requestPayload, signingInfo, vps.vp_token)]; // Generate VP Token
                    case 4:
                        vp_token_s = _a.sent(); // Generate VP Token
                        _a.label = 5;
                    case 5:
                        tokens = {
                            id_token: id_token_s,
                            vp_token: vp_token_s
                        };
                        return [2 /*return*/, Promise.resolve(tokens)];
                    case 6:
                        err_5 = _a.sent();
                        return [2 /*return*/, Promise.reject(err_5)];
                    case 7: return [2 /*return*/];
                }
            });
        });
    };
    /**
     *
     * @param {string} response - A DID SIOP response which needs to be validated
     * @param {CheckParams} checkParams - Specific field values in the JWT which needs to be validated
     * @returns {Promise<JWT.JWTObject | ErrorResponse.SIOPErrorResponse>} - A promise wich will resolve either to a decoded id_token (JWT)
     * or an error response
     * @remarks This method first decodes the response JWT.
     * Then checks if it is an error response and if so, returns it.
     * Else it will proceed to validate the JWT (id_token).
     * Fields in the JWT header and payload will be checked for availability.
     * Then the id_token will be validated against 'checkParams'.
     * Then the signature of the id_token is verified using public key information derived from
     * the 'kid' field in the header and 'did' field in the payload.
     * If the verification is successful, this method returns the decoded id_token (JWT).
     * https://identity.foundation/did-siop/#siop-response-validation
     */
    DidSiopResponse.validateResponse = function (response, checkParams) {
        return __awaiter(this, void 0, void 0, function () {
            var decodedHeader, decodedPayload, errorResponse, jwkThumbprint, publicKeyInfo, identity, didPubKey, err_6, validity;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        try {
                            errorResponse = ErrorResponse.checkErrorResponse(response);
                            if (errorResponse)
                                return [2 /*return*/, errorResponse];
                            decodedHeader = JSON.parse(base64url_1.default.decode(response.split('.')[0]));
                            decodedPayload = JSON.parse(base64url_1.default.decode(response.split('.')[1]));
                        }
                        catch (err) {
                            return [2 /*return*/, Promise.reject(err)];
                        }
                        if (!((decodedHeader.kid && !decodedHeader.kid.match(/^ *$/)) &&
                            (decodedPayload.iss && !decodedPayload.iss.match(/^ *$/)) &&
                            (decodedPayload.aud && !decodedPayload.aud.match(/^ *$/)) &&
                            (decodedPayload.did && !decodedPayload.did.match(/^ *$/)) &&
                            (decodedPayload.sub && !decodedPayload.sub.match(/^ *$/)) &&
                            (decodedPayload.sub_jwk && !JSON.stringify(decodedPayload.sub_jwk).match(/^ *$/)))) return [3 /*break*/, 5];
                        if (decodedPayload.iss !== 'https://self-issued.me')
                            return [2 /*return*/, Promise.reject(new Error(ERRORS.NON_SIOP_FLOW))];
                        if (decodedPayload.aud !== checkParams.redirect_uri)
                            return [2 /*return*/, Promise.reject(new Error(ERRORS.INCORRECT_AUDIENCE))];
                        if (decodedPayload.nonce && (decodedPayload.nonce !== checkParams.nonce))
                            return [2 /*return*/, Promise.reject(new Error(ERRORS.INCORRECT_NONCE))];
                        if (checkParams.validBefore) {
                            if (decodedPayload.iat) {
                                if (decodedPayload.iat + checkParams.validBefore <= Date.now())
                                    return [2 /*return*/, Promise.reject(new Error(ERRORS.JWT_VALIDITY_EXPIRED))];
                            }
                            else {
                                return [2 /*return*/, Promise.reject(new Error(ERRORS.NO_ISSUED_TIME))];
                            }
                        }
                        if (checkParams.isExpirable) {
                            if (decodedPayload.exp) {
                                if (decodedPayload.exp <= Date.now())
                                    return [2 /*return*/, Promise.reject(new Error(ERRORS.JWT_VALIDITY_EXPIRED))];
                            }
                            else {
                                return [2 /*return*/, Promise.reject(new Error(ERRORS.NO_EXPIRATION))];
                            }
                        }
                        jwkThumbprint = JWKUtils_1.calculateThumbprint(decodedPayload.sub_jwk);
                        if (jwkThumbprint !== decodedPayload.sub)
                            return [2 /*return*/, Promise.reject(new Error(ERRORS.INVALID_JWK_THUMBPRINT))];
                        publicKeyInfo = void 0;
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 3, , 4]);
                        identity = new Identity_1.Identity();
                        return [4 /*yield*/, identity.resolve(decodedPayload.did)];
                    case 2:
                        _a.sent();
                        didPubKey = identity.extractAuthenticationKeys().find(function (authKey) { return authKey.id === decodedHeader.kid; });
                        if (didPubKey) {
                            publicKeyInfo = {
                                key: didPubKey.publicKey,
                                kid: didPubKey.id,
                                alg: didPubKey.alg,
                                format: didPubKey.format
                            };
                        }
                        else {
                            throw new Error(ERRORS.PUBLIC_KEY_ERROR);
                        }
                        return [3 /*break*/, 4];
                    case 3:
                        err_6 = _a.sent();
                        return [2 /*return*/, Promise.reject(ERRORS.PUBLIC_KEY_ERROR)];
                    case 4:
                        validity = false;
                        if (publicKeyInfo) {
                            validity = JWT.verify(response, publicKeyInfo);
                        }
                        else {
                            return [2 /*return*/, Promise.reject(ERRORS.PUBLIC_KEY_ERROR)];
                        }
                        if (validity)
                            return [2 /*return*/, {
                                    header: decodedHeader,
                                    payload: decodedPayload,
                                }];
                        return [2 /*return*/, Promise.reject(new Error(ERRORS.INVALID_SIGNATURE_ERROR))];
                    case 5: return [2 /*return*/, Promise.reject(new Error(ERRORS.MALFORMED_JWT_ERROR))];
                }
            });
        });
    };
    return DidSiopResponse;
}());
exports.DidSiopResponse = DidSiopResponse;
//# sourceMappingURL=Response.js.map