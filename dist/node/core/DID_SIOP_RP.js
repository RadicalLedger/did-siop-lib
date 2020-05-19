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
exports.__esModule = true;
var Response_1 = require("./Response");
var Request_1 = require("./Request");
var Identity_1 = require("./Identity");
var globals_1 = require("./globals");
var JWKUtils_1 = require("./JWKUtils");
var Signers_1 = require("./Signers");
var Verifiers_1 = require("./Verifiers");
var Utils_1 = require("./Utils");
var ERRORS = Object.freeze({
    NO_SIGNING_INFO: 'Atleast one SigningInfo is required',
    INVALID_KEY_TYPE: 'Invalid key type',
    KEY_MISMATCH: 'Public and private keys do not match'
});
var RP = /** @class */ (function () {
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
    RP.prototype.addSigningParams = function (key, kid, format, algorithm) {
        try {
            algorithm = typeof algorithm === 'string' ? Utils_1.getAlgorithm(algorithm) : algorithm;
            format = typeof format === 'string' ? Utils_1.getKeyFormat(format) : format;
            var didPublicKey = this.identity.getPublicKey(kid);
            var publicKeyInfo = {
                key: didPublicKey.keyString,
                kid: kid,
                use: 'sig',
                kty: globals_1.KTYS[didPublicKey.kty],
                alg: globals_1.ALGORITHMS[algorithm],
                format: didPublicKey.format,
                isPrivate: false
            };
            var privateKeyInfo = {
                key: key,
                kid: kid,
                use: 'sig',
                kty: globals_1.KTYS[didPublicKey.kty],
                alg: globals_1.ALGORITHMS[algorithm],
                format: format,
                isPrivate: true
            };
            var privateKey = void 0;
            var publicKey = void 0;
            var signer = void 0, verifier = void 0;
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
                        publicKey = didPublicKey.keyString;
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
                    throw new Error(ERRORS.INVALID_KEY_TYPE);
                }
            }
            if (Utils_1.checkKeyPair(privateKey, publicKey, signer, verifier, algorithm)) {
                this.signing_info_set.push({
                    alg: algorithm,
                    publicKey_kid: kid,
                    privateKey: privateKey
                });
            }
            else {
                throw new Error(ERRORS.KEY_MISMATCH);
            }
        }
        catch (err) {
            throw err;
        }
    };
    RP.prototype.removeSigningParams = function (kid) {
        try {
            this.signing_info_set = this.signing_info_set.filter(function (s) { return s.publicKey_kid !== kid; });
        }
        catch (err) {
            throw err;
        }
    };
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
                    case 2: return [2 /*return*/, Promise.reject(new Error(ERRORS.NO_SIGNING_INFO))];
                    case 3:
                        err_2 = _a.sent();
                        return [2 /*return*/, Promise.reject(err_2)];
                    case 4: return [2 /*return*/];
                }
            });
        });
    };
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
                        return [2 /*return*/, Promise.reject(ERRORS.NO_SIGNING_INFO)];
                    case 3: return [2 /*return*/];
                }
            });
        });
    };
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
//# sourceMappingURL=DID_SIOP_RP.js.map