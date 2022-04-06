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
Object.defineProperty(exports, "__esModule", { value: true });
var Response_1 = require("./Response");
var Request_1 = require("./Request");
var Identity_1 = require("./Identity");
var globals_1 = require("./globals");
var JWKUtils_1 = require("./JWKUtils");
var Signers_1 = require("./Signers");
var Verifiers_1 = require("./Verifiers");
var Utils_1 = require("./Utils");
exports.ERRORS = Object.freeze({
    NO_SIGNING_INFO: 'At least one public key must be confirmed with related private key',
    NO_PUBLIC_KEY: 'No public key matches given private key',
});
/**
 * @classdesc This class provides the Relying Party functionality of DID based Self Issued OpenID Connect
 * @property {RPInfo} - Used to hold Relying Party information needed in issuing requests (ex:- redirect_uri)
 * @property {Identity} identity  - Used to store Decentralized Identity information of the Relying Party
 * @property {SigningInfo[]} signing_info_set - Used to store a list of cryptographic information used to sign DID SIOP requests
 */
var RP = /** @class */ (function () {
    /**
     * @private
     * @constructor
     * @param {string} redirect_uri - Redirect uri of the RP. Response from the Provider is sent to this uri
     * @param {string} did - Decentralized Identity of the Relying Party
     * @param {any} registration - Registration information of the Relying Party
     * https://openid.net/specs/openid-connect-core-1_0.html#RegistrationParameter
     * @param {DidDocument} [did_doc] - DID Document of the RP. Optional
     * @remarks - This is a private constructor used inside static async method getRP
     */
    function RP(redirect_uri, did, registration, did_doc) {
        this.identity = new Identity_1.Identity();
        this.signing_info_set = [];
        this.info = {
            redirect_uri: redirect_uri,
            did: did,
            registration: registration,
            did_doc: did_doc
        };
    }
    /**
     * @param {string} redirect_uri - Redirect uri of the RP. Response from the Provider is sent to this uri
     * @param {string} did - Decentralized Identity of the Relying Party
     * @param {any} registration - Registration information of the Relying Party
     * https://openid.net/specs/openid-connect-core-1_0.html#RegistrationParameter
     * @param {DidDocument} [did_doc] - DID Document of the RP. Optional
     * @returns {Promise<RP>} - A Promise which resolves to an instance of RP class
     * @remarks Creating RP instances involves some async code and cannot be implemented as a constructor.
     * Hence this static method is used in place of the constructor.
     */
    RP.getRP = function (redirect_uri, did, registration, did_doc) {
        return __awaiter(this, void 0, void 0, function () {
            var rp, err_1;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 4, , 5]);
                        rp = new RP(redirect_uri, did, registration, did_doc);
                        if (!did_doc) return [3 /*break*/, 1];
                        rp.identity.setDocument(did_doc, did);
                        return [3 /*break*/, 3];
                    case 1: return [4 /*yield*/, rp.identity.resolve(did)];
                    case 2:
                        _a.sent();
                        _a.label = 3;
                    case 3: return [2 /*return*/, rp];
                    case 4:
                        err_1 = _a.sent();
                        return [2 /*return*/, Promise.reject(err_1)];
                    case 5: return [2 /*return*/];
                }
            });
        });
    };
    /**
     * @param {string} key - Private part of any cryptographic key listed in the 'authentication' field of RP's DID Document
     * @param {string} [kid] - kid value of the key. Optional and not used
     * @param {KEY_FORMATS| string} [format] - Format in which the private key is supplied. Optional and not used
     * @param {ALGORITHMS} [algorithm] - Algorithm to use the key with. Optional and not used
     * @returns {string} - kid of the added key
     * @remarks This method is used to add signing information to 'signing_info_set'.
     * All optional parameters are not used and only there to make the library backward compatible.
     * Instead of using those optional parameters, given key is iteratively tried with
     * every public key listed in the 'authentication' field of RP's DID Document and every key format
     * until a compatible combination of those information which can be used for the signing process is found.
     */
    RP.prototype.addSigningParams = function (key, kid, format, algorithm) {
        try {
            if (format) { }
            if (algorithm) { }
            if (kid) { }
            var didPublicKeySet = this.identity.extractAuthenticationKeys();
            for (var _i = 0, didPublicKeySet_1 = didPublicKeySet; _i < didPublicKeySet_1.length; _i++) {
                var didPublicKey = didPublicKeySet_1[_i];
                var publicKeyInfo = {
                    key: didPublicKey.publicKey,
                    kid: didPublicKey.id,
                    use: 'sig',
                    kty: globals_1.KTYS[didPublicKey.kty],
                    alg: globals_1.ALGORITHMS[didPublicKey.alg],
                    format: didPublicKey.format,
                    isPrivate: false
                };
                for (var key_format in globals_1.KEY_FORMATS) {
                    var privateKeyInfo = {
                        key: key,
                        kid: didPublicKey.id,
                        use: 'sig',
                        kty: globals_1.KTYS[didPublicKey.kty],
                        alg: globals_1.ALGORITHMS[didPublicKey.alg],
                        format: globals_1.KEY_FORMATS[key_format],
                        isPrivate: true
                    };
                    var privateKey = void 0;
                    var publicKey = void 0;
                    var signer = void 0, verifier = void 0;
                    try {
                        switch (didPublicKey.kty) {
                            case globals_1.KTYS.RSA:
                                {
                                    privateKey = JWKUtils_1.RSAKey.fromKey(privateKeyInfo);
                                    publicKey = JWKUtils_1.RSAKey.fromKey(publicKeyInfo);
                                    signer = new Signers_1.RSASigner();
                                    verifier = new Verifiers_1.RSAVerifier();
                                    break;
                                }
                                ;
                            case globals_1.KTYS.EC: {
                                if (didPublicKey.format === globals_1.KEY_FORMATS.ETHEREUM_ADDRESS) {
                                    privateKey = JWKUtils_1.ECKey.fromKey(privateKeyInfo);
                                    publicKey = didPublicKey.publicKey;
                                    signer = new Signers_1.ES256KRecoverableSigner();
                                    verifier = new Verifiers_1.ES256KRecoverableVerifier();
                                }
                                else {
                                    privateKey = JWKUtils_1.ECKey.fromKey(privateKeyInfo);
                                    publicKey = JWKUtils_1.ECKey.fromKey(publicKeyInfo);
                                    signer = new Signers_1.ECSigner();
                                    verifier = new Verifiers_1.ECVerifier();
                                }
                                break;
                            }
                            case globals_1.KTYS.OKP:
                                {
                                    privateKey = JWKUtils_1.OKP.fromKey(privateKeyInfo);
                                    publicKey = JWKUtils_1.OKP.fromKey(publicKeyInfo);
                                    signer = new Signers_1.OKPSigner();
                                    verifier = new Verifiers_1.OKPVerifier();
                                    break;
                                }
                                ;
                            default: {
                                continue;
                            }
                        }
                        if (Utils_1.checkKeyPair(privateKey, publicKey, signer, verifier, didPublicKey.alg)) {
                            this.signing_info_set.push({
                                alg: didPublicKey.alg,
                                kid: didPublicKey.id,
                                key: key,
                                format: globals_1.KEY_FORMATS[key_format],
                            });
                            return didPublicKey.id;
                        }
                    }
                    catch (err) {
                        continue;
                    }
                }
            }
            throw new Error(exports.ERRORS.NO_PUBLIC_KEY);
        }
        catch (err) {
            throw err;
        }
    };
    /**
     * @param {string} kid - kid value of the SigningInfo which needs to be removed from the list
     * @remarks This method is used to remove a certain SigningInfo (key) which has the given kid value from the list.
     */
    RP.prototype.removeSigningParams = function (kid) {
        try {
            this.signing_info_set = this.signing_info_set.filter(function (s) { return s.kid !== kid; });
        }
        catch (err) {
            throw err;
        }
    };
    /**
     * @param {any} [options = {}] - Any optional field which should be included in the request JWT. Any field which is not supported
     * at Provider's end will be ignored
     * @returns {Promise<string>} - A Promise which resolves to a DID SIOP request
     * @remarks This method is used to generate a request sent to a DID SIOP Provider.
     */
    RP.prototype.generateRequest = function (options) {
        if (options === void 0) { options = {}; }
        return __awaiter(this, void 0, void 0, function () {
            var signing_info, err_2;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 3, , 4]);
                        if (!(this.signing_info_set.length > 0)) return [3 /*break*/, 2];
                        signing_info = this.signing_info_set[Math.floor(Math.random() * this.signing_info_set.length)];
                        return [4 /*yield*/, Request_1.DidSiopRequest.generateRequest(this.info, signing_info, options)];
                    case 1: return [2 /*return*/, _a.sent()];
                    case 2: return [2 /*return*/, Promise.reject(new Error(exports.ERRORS.NO_SIGNING_INFO))];
                    case 3:
                        err_2 = _a.sent();
                        return [2 /*return*/, Promise.reject(err_2)];
                    case 4: return [2 /*return*/];
                }
            });
        });
    };
    /**
     * @param {string} request_uri - A uri from which a pre-configured and signed request JWT can be obtained
     * @param {any} [options = {}] - Any optional field which should be included in the request JWT. Any field which is not supported
     * at Provider's end will be ignored
     * @returns {Promise<string>} - A Promise which resolves to a DID SIOP request
     * @remarks This method is used to generate a request which has 'request_uri' in place of the 'request' parameter.
     * https://identity.foundation/did-siop/#generate-siop-request
     */
    RP.prototype.generateUriRequest = function (request_uri, options) {
        if (options === void 0) { options = {}; }
        return __awaiter(this, void 0, void 0, function () {
            var err_3;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 2, , 3]);
                        this.info.request_uri = request_uri;
                        return [4 /*yield*/, this.generateRequest(options)];
                    case 1: return [2 /*return*/, _a.sent()];
                    case 2:
                        err_3 = _a.sent();
                        return [2 /*return*/, Promise.reject(exports.ERRORS.NO_SIGNING_INFO)];
                    case 3: return [2 /*return*/];
                }
            });
        });
    };
    /**
     * @param {string} response - A DID SIOP response
     * @param {CheckParams} [checkParams = {redirect_uri: this.info.redirect_uri}] - Parameters against which the response needs to be validated
     * @returns {Promise<JWT.JWTObject> | SIOPErrorResponse} - A Promise which resolves either to a decoded response or a SIOPErrorResponse
     * @remarks This method is used to validate responses coming from DID SIOP Providers.
     */
    RP.prototype.validateResponse = function (response, checkParams) {
        if (checkParams === void 0) { checkParams = { redirect_uri: this.info.redirect_uri }; }
        return __awaiter(this, void 0, void 0, function () {
            var err_4;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 2, , 3]);
                        return [4 /*yield*/, Response_1.DidSiopResponse.validateResponse(response, checkParams)];
                    case 1: return [2 /*return*/, _a.sent()];
                    case 2:
                        err_4 = _a.sent();
                        return [2 /*return*/, Promise.reject(err_4)];
                    case 3: return [2 /*return*/];
                }
            });
        });
    };
    return RP;
}());
exports.RP = RP;
//# sourceMappingURL=RP.js.map