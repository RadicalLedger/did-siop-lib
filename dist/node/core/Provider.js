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
Object.defineProperty(exports, "__esModule", { value: true });
var Verifiers_1 = require("./Verifiers");
var Signers_1 = require("./Signers");
var JWKUtils_1 = require("./JWKUtils");
var globals_1 = require("./globals");
var Response_1 = require("./Response");
var Identity_1 = require("./Identity");
var Request_1 = require("./Request");
var Utils_1 = require("./Utils");
var ErrorResponse = __importStar(require("./ErrorResponse"));
exports.ERRORS = Object.freeze({
    NO_SIGNING_INFO: 'At least one public key must be confirmed with related private key',
    UNRESOLVED_IDENTITY: 'Unresolved identity',
    NO_PUBLIC_KEY: 'No public key matches given private key',
});
/**
 * @classdesc This class provides the functionality of a DID based Self Issued OpenID Connect Provider
 * @property {Identity} identity  - Used to store Decentralized Identity information of the Provider (end user)
 * @property {SigningInfo[]} signing_info_set - Used to store a list of cryptographic information used to sign id_tokens
 */
var Provider = /** @class */ (function () {
    function Provider() {
        this.identity = new Identity_1.Identity();
        this.signing_info_set = [];
    }
    /**
     * @param {string} did - The DID of the provider (end user)
     * @param {DidDocument} [doc] - DID Document of the provider (end user).
     * @remarks This method is used to set the decentralized identity for the provider (end user).
     * doc parameter is optional and if provided it will be used to directly set the identity.
     * Otherwise the DID Document will be resolved over a related network.
     */
    Provider.prototype.setUser = function (did, doc) {
        return __awaiter(this, void 0, void 0, function () {
            var err_1;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 4, , 5]);
                        if (!doc) return [3 /*break*/, 1];
                        this.identity.setDocument(doc, did);
                        return [3 /*break*/, 3];
                    case 1: return [4 /*yield*/, this.identity.resolve(did)];
                    case 2:
                        _a.sent();
                        _a.label = 3;
                    case 3: return [3 /*break*/, 5];
                    case 4:
                        err_1 = _a.sent();
                        throw err_1;
                    case 5: return [2 /*return*/];
                }
            });
        });
    };
    /**
     * @param {string} key - Private part of any cryptographic key listed in the 'authentication' field of the user's DID Document
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
    Provider.prototype.addSigningParams = function (key, kid, format, algorithm) {
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
    Provider.prototype.removeSigningParams = function (kid) {
        try {
            this.signing_info_set = this.signing_info_set.filter(function (s) { return s.kid !== kid; });
        }
        catch (err) {
            throw err;
        }
    };
    /**
     * @param {string} request - A DID SIOP request
     * @returns {Promise<JWT.JWTObject>} - A Promise which resolves to a decoded request JWT
     * @remarks This method is used to validate requests coming from Relying Parties.
     */
    Provider.prototype.validateRequest = function (request) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                try {
                    return [2 /*return*/, Request_1.DidSiopRequest.validateRequest(request)];
                }
                catch (err) {
                    return [2 /*return*/, Promise.reject(err)];
                }
                return [2 /*return*/];
            });
        });
    };
    /**
     * @param {any} requestPayload - Payload of the request JWT for which a response needs to be generated
     * @param {number} expiresIn - Number of miliseconds under which the generated response is valid. Relying Parties can
     * either consider this value or ignore it
     * @returns {Promise<string>} - A Promise which resolves to an encoded DID SIOP response JWT
     * @remarks This method is used to generate a response to a given DID SIOP request.
     */
    Provider.prototype.generateResponse = function (requestPayload, expiresIn) {
        if (expiresIn === void 0) { expiresIn = 1000; }
        return __awaiter(this, void 0, void 0, function () {
            var signing_info, err_2;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 4, , 5]);
                        if (!(this.signing_info_set.length > 0)) return [3 /*break*/, 3];
                        signing_info = this.signing_info_set[Math.floor(Math.random() * this.signing_info_set.length)];
                        if (!this.identity.isResolved()) return [3 /*break*/, 2];
                        return [4 /*yield*/, Response_1.DidSiopResponse.generateResponse(requestPayload, signing_info, this.identity, expiresIn)];
                    case 1: return [2 /*return*/, _a.sent()];
                    case 2: return [2 /*return*/, Promise.reject(new Error(exports.ERRORS.UNRESOLVED_IDENTITY))];
                    case 3: return [2 /*return*/, Promise.reject(new Error(exports.ERRORS.NO_SIGNING_INFO))];
                    case 4:
                        err_2 = _a.sent();
                        return [2 /*return*/, Promise.reject(err_2)];
                    case 5: return [2 /*return*/];
                }
            });
        });
    };
    /**
     * @param {string} errorMessage - Message of a specific SIOPErrorResponse
     * @returns {string} - Encoded SIOPErrorResponse object
     * @remarks This method is used to generate error responses.
     */
    Provider.prototype.generateErrorResponse = function (errorMessage) {
        try {
            return ErrorResponse.getBase64URLEncodedError(errorMessage);
        }
        catch (err) {
            throw err;
        }
    };
    return Provider;
}());
exports.Provider = Provider;
//# sourceMappingURL=Provider.js.map