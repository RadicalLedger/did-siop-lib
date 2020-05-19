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
var globals_1 = require("./globals");
var config_1 = require("./config");
var axios = require('axios').default;
var toChecksumAddress = require('ethereum-checksum-address').toChecksumAddress;
exports.ERRORS = Object.freeze({
    DOCUMENT_RESOLUTION_ERROR: 'Cannot resolve document for did',
    INVALID_DID_ERROR: 'Invalid did',
    UNSUPPORTED_KEY_TYPE: 'Unsupported key type',
    UNSUPPORTED_KEY_FORMAT: 'Unsupported key format',
    NO_MATCHING_PUBLIC_KEY: 'No public key matching kid',
    UNRESOLVED_DOCUMENT: 'Unresolved document',
    INVALID_DOCUMENT: 'Invalid did document',
});
var Identity = /** @class */ (function () {
    function Identity() {
        this.doc = {
            '@context': '',
            id: '',
            authentication: [],
        };
    }
    Identity.prototype.resolve = function (did) {
        return __awaiter(this, void 0, void 0, function () {
            var result, err_1;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 2, , 3]);
                        return [4 /*yield*/, axios.get(config_1.RESOLVER_URL + did)];
                    case 1:
                        result = _a.sent();
                        if (result &&
                            result.data &&
                            result.data.didDocument &&
                            result.data.didDocument['@context'] === 'https://w3id.org/did/v1' &&
                            result.data.didDocument.id == did &&
                            result.data.didDocument.authentication &&
                            result.data.didDocument.authentication.length > 0) {
                            this.doc = result.data.didDocument;
                            return [2 /*return*/, this.doc.id];
                        }
                        throw new Error(exports.ERRORS.INVALID_DID_ERROR);
                    case 2:
                        err_1 = _a.sent();
                        throw new Error(exports.ERRORS.DOCUMENT_RESOLUTION_ERROR);
                    case 3: return [2 /*return*/];
                }
            });
        });
    };
    Identity.prototype.isResolved = function () {
        return this.doc.id !== '';
    };
    Identity.prototype.getPublicKey = function (kid) {
        if (!this.isResolved())
            throw new Error(exports.ERRORS.UNRESOLVED_DOCUMENT);
        for (var _i = 0, _a = this.doc.authentication; _i < _a.length; _i++) {
            var method = _a[_i];
            if (method.id && method.id === kid)
                return getPublicKeyFromDifferentTypes(method);
            if (method.publicKey && method.publicKey.includes(kid)) {
                for (var _b = 0, _c = this.doc.publicKey; _b < _c.length; _b++) {
                    var pub = _c[_b];
                    if (pub.id === kid)
                        return getPublicKeyFromDifferentTypes(pub);
                }
            }
            if (method && method === kid) {
                for (var _d = 0, _e = this.doc.publicKey; _d < _e.length; _d++) {
                    var pub = _e[_d];
                    if (pub.id === kid)
                        return getPublicKeyFromDifferentTypes(pub);
                }
                //Implement other verification methods here
            }
        }
        throw new Error(exports.ERRORS.NO_MATCHING_PUBLIC_KEY);
    };
    Identity.prototype.getDocument = function () {
        return this.doc;
    };
    Identity.prototype.setDocument = function (doc, did) {
        if (doc['@context'] === 'https://w3id.org/did/v1' &&
            doc.id == did &&
            doc.authentication &&
            doc.authentication.length > 0) {
            this.doc = doc;
        }
        else {
            throw new Error(exports.ERRORS.INVALID_DOCUMENT);
        }
    };
    return Identity;
}());
exports.Identity = Identity;
function getKtyFromKeyType(type) {
    switch (type) {
        case 'RsaVerificationKey2018': return globals_1.KTYS.RSA;
        case 'OpenPgpVerificationKey2019': return globals_1.KTYS.RSA;
        case 'EcdsaSecp256k1VerificationKey2019': return globals_1.KTYS.EC;
        case 'Ed25519VerificationKey2018': return globals_1.KTYS.OKP;
        case 'ED25519SignatureVerification': return globals_1.KTYS.OKP;
        case 'Curve25519EncryptionPublicKey': return globals_1.KTYS.OKP;
        case 'Secp256k1SignatureVerificationKey2018': return globals_1.KTYS.OKP;
        case 'Secp256k1VerificationKey2018': return globals_1.KTYS.EC;
        default: throw new Error(exports.ERRORS.UNSUPPORTED_KEY_TYPE);
    }
}
function getPublicKeyFromDifferentTypes(key) {
    if (!key)
        throw new Error(exports.ERRORS.UNSUPPORTED_KEY_TYPE);
    if (key.publicKeyBase64) {
        return {
            id: key.id,
            kty: getKtyFromKeyType(key.type),
            format: globals_1.KEY_FORMATS.BASE64,
            keyString: key.publicKeyBase64,
        };
    }
    else if (key.publicKeyBase58) {
        return {
            id: key.id,
            kty: getKtyFromKeyType(key.type),
            format: globals_1.KEY_FORMATS.BASE58,
            keyString: key.publicKeyBase58,
        };
    }
    else if (key.publicKeyHex) {
        return {
            id: key.id,
            kty: getKtyFromKeyType(key.type),
            format: globals_1.KEY_FORMATS.HEX,
            keyString: key.publicKeyHex,
        };
    }
    else if (key.publicKeyPem) {
        var format = key.publicKeyPem.indexOf('-----BEGIN RSA PUBLIC KEY-----') > -1 ? globals_1.KEY_FORMATS.PKCS1_PEM : globals_1.KEY_FORMATS.PKCS8_PEM;
        return {
            id: key.id,
            kty: getKtyFromKeyType(key.type),
            format: format,
            keyString: key.publicKeyPem,
        };
    }
    else if (key.publicKeyJwk) {
        return {
            id: key.id,
            kty: getKtyFromKeyType(key.type),
            format: globals_1.KEY_FORMATS.JWK,
            keyString: JSON.stringify(key.publicKeyJwk),
        };
    }
    else if (key.publicKeyPgp) {
        var format = key.publicKeyPgp.indexOf('-----BEGIN RSA PUBLIC KEY-----') > -1 ? globals_1.KEY_FORMATS.PKCS1_PEM : globals_1.KEY_FORMATS.PKCS8_PEM;
        return {
            id: key.id,
            kty: getKtyFromKeyType(key.type),
            format: format,
            keyString: key.publicKeyPgp,
        };
    }
    else if (key.ethereumAddress) {
        return {
            id: key.id,
            kty: getKtyFromKeyType(key.type),
            format: globals_1.KEY_FORMATS.ETHEREUM_ADDRESS,
            keyString: toChecksumAddress(key.ethereumAddress),
        };
    }
    else if (key.address) {
        return {
            id: key.id,
            kty: getKtyFromKeyType(key.type),
            format: globals_1.KEY_FORMATS.ADDRESS,
            keyString: key.address,
        };
    }
    else
        throw new Error(exports.ERRORS.UNSUPPORTED_KEY_FORMAT);
}
//# sourceMappingURL=Identity.js.map