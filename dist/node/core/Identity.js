"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
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
var Utils_1 = require("./Utils");
var axios = require('axios').default;
var toChecksumAddress = require('ethereum-checksum-address').toChecksumAddress;
exports.ERRORS = Object.freeze({
    DOCUMENT_RESOLUTION_ERROR: 'Cannot resolve document for did',
    INVALID_DID_ERROR: 'Invalid did',
    UNSUPPORTED_KEY_TYPE: 'Unsupported key type',
    UNSUPPORTED_KEY_FORMAT: 'Unsupported key format',
    NO_MATCHING_PUBLIC_KEY: 'No public key matching kid',
    UNSUPPORTED_PUBLIC_KEY_METHOD: 'Unsupported public key method',
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
        this.keySet = [];
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
                        return [3 /*break*/, 3];
                    case 2:
                        err_1 = _a.sent();
                        throw new Error(exports.ERRORS.DOCUMENT_RESOLUTION_ERROR);
                    case 3:
                        if (result &&
                            result.data &&
                            result.data.didDocument &&
                            //result.data.didDocument['@context'] === 'https://w3id.org/did/v1' &&
                            result.data.didDocument.id == did &&
                            result.data.didDocument.authentication &&
                            result.data.didDocument.authentication.length > 0) {
                            this.doc = result.data.didDocument;
                            this.keySet = [];
                            return [2 /*return*/, this.doc.id];
                        }
                        throw new Error(exports.ERRORS.INVALID_DID_ERROR);
                }
            });
        });
    };
    Identity.prototype.isResolved = function () {
        return this.doc.id !== '';
    };
    Identity.prototype.extractAuthenticationKeys = function (extractor) {
        if (!extractor)
            extractor = exports.uniExtractor;
        if (!this.isResolved())
            throw new Error(exports.ERRORS.UNRESOLVED_DOCUMENT);
        if (this.keySet.length === 0) {
            for (var _i = 0, _a = this.doc.authentication; _i < _a.length; _i++) {
                var method = _a[_i];
                if (method.id && method.type) {
                    try {
                        this.keySet.push(extractor.extract(method));
                    }
                    catch (err) {
                        continue;
                    }
                }
                if (method.publicKey) {
                    for (var _b = 0, _c = method.publicKey; _b < _c.length; _b++) {
                        var key = _c[_b];
                        for (var _d = 0, _e = this.doc.publicKey; _d < _e.length; _d++) {
                            var pub = _e[_d];
                            if (pub.id === key || pub.id === this.doc.id + key) {
                                try {
                                    this.keySet.push(extractor.extract(pub));
                                }
                                catch (err) {
                                    continue;
                                }
                            }
                        }
                    }
                }
                if (typeof method === 'string') {
                    for (var _f = 0, _g = this.doc.publicKey; _f < _g.length; _f++) {
                        var pub = _g[_f];
                        if (pub.id === method) {
                            try {
                                this.keySet.push(extractor.extract(pub));
                            }
                            catch (err) {
                                continue;
                            }
                        }
                    }
                    //Implement other verification methods here
                }
            }
        }
        return this.keySet;
    };
    Identity.prototype.getDocument = function () {
        return this.doc;
    };
    Identity.prototype.setDocument = function (doc, did) {
        if (
        //doc['@context'] === 'https://w3id.org/did/v1' &&
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
var DidVerificationKeyExtractor = /** @class */ (function () {
    function DidVerificationKeyExtractor(names, next) {
        this.names = [];
        if (typeof names === 'string') {
            this.names.push(names.toUpperCase());
        }
        else {
            for (var _i = 0, names_1 = names; _i < names_1.length; _i++) {
                var name_1 = names_1[_i];
                this.names.push(name_1.toUpperCase());
            }
        }
        if (next) {
            this.next = next;
        }
        else {
            this.next = new EmptyDidVerificationKeyExtractor();
        }
    }
    return DidVerificationKeyExtractor;
}());
exports.DidVerificationKeyExtractor = DidVerificationKeyExtractor;
var EmptyDidVerificationKeyExtractor = /** @class */ (function () {
    function EmptyDidVerificationKeyExtractor() {
    }
    EmptyDidVerificationKeyExtractor.prototype.extract = function (method) {
        if (method) { }
        throw new Error(exports.ERRORS.UNSUPPORTED_PUBLIC_KEY_METHOD);
    };
    ;
    return EmptyDidVerificationKeyExtractor;
}());
var JwsVerificationKey2020Extractor = /** @class */ (function (_super) {
    __extends(JwsVerificationKey2020Extractor, _super);
    function JwsVerificationKey2020Extractor() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    JwsVerificationKey2020Extractor.prototype.extract = function (method) {
        if (!method || !method.id || !method.type)
            throw new Error(exports.ERRORS.NO_MATCHING_PUBLIC_KEY);
        if (this.names.includes(method.type.toUpperCase())) {
            if (method.publicKeyJwk) {
                return {
                    id: method.id,
                    kty: Utils_1.getKeyType(method.publicKeyJwk.kty),
                    alg: Utils_1.getAlgorithm(method.publicKeyJwk.alg),
                    format: globals_1.KEY_FORMATS.JWK,
                    publicKey: method.publicKeyJwk
                };
            }
            else {
                throw new Error(exports.ERRORS.UNSUPPORTED_PUBLIC_KEY_METHOD);
            }
        }
        else {
            return this.next.extract(method);
        }
    };
    return JwsVerificationKey2020Extractor;
}(DidVerificationKeyExtractor));
var Ed25519VerificationKeyExtractor = /** @class */ (function (_super) {
    __extends(Ed25519VerificationKeyExtractor, _super);
    function Ed25519VerificationKeyExtractor() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    Ed25519VerificationKeyExtractor.prototype.extract = function (method) {
        if (!method || !method.id || !method.type)
            throw new Error(exports.ERRORS.NO_MATCHING_PUBLIC_KEY);
        if (this.names.includes(method.type.toUpperCase())) {
            var extracted = {
                id: method.id,
                kty: globals_1.KTYS.OKP,
                alg: globals_1.ALGORITHMS.EdDSA,
                format: globals_1.KEY_FORMATS.HEX,
                publicKey: ''
            };
            return getVerificationKeyFromDifferentFormats(method, extracted);
        }
        else {
            return this.next.extract(method);
        }
    };
    return Ed25519VerificationKeyExtractor;
}(DidVerificationKeyExtractor));
var GpgVerificationKey2020Extractor = /** @class */ (function (_super) {
    __extends(GpgVerificationKey2020Extractor, _super);
    function GpgVerificationKey2020Extractor() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    GpgVerificationKey2020Extractor.prototype.extract = function (method) {
        if (!method || !method.id || !method.type)
            throw new Error(exports.ERRORS.NO_MATCHING_PUBLIC_KEY);
        if (this.names.includes(method.type.toUpperCase())) {
            if (method.publicKeyGpg) {
                return {
                    id: method.id,
                    kty: globals_1.KTYS.RSA,
                    alg: globals_1.ALGORITHMS.RS256,
                    format: globals_1.KEY_FORMATS.PKCS8_PEM,
                    publicKey: method.publicKeyGpg
                };
            }
            else {
                throw new Error(exports.ERRORS.UNSUPPORTED_PUBLIC_KEY_METHOD);
            }
        }
        else {
            return this.next.extract(method);
        }
    };
    return GpgVerificationKey2020Extractor;
}(DidVerificationKeyExtractor));
var RsaVerificationKeyExtractor = /** @class */ (function (_super) {
    __extends(RsaVerificationKeyExtractor, _super);
    function RsaVerificationKeyExtractor() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    RsaVerificationKeyExtractor.prototype.extract = function (method) {
        if (!method || !method.id || !method.type)
            throw new Error(exports.ERRORS.NO_MATCHING_PUBLIC_KEY);
        if (this.names.includes(method.type.toUpperCase())) {
            var extracted = {
                id: method.id,
                kty: globals_1.KTYS.RSA,
                alg: globals_1.ALGORITHMS.RS256,
                format: globals_1.KEY_FORMATS.HEX,
                publicKey: ''
            };
            return getVerificationKeyFromDifferentFormats(method, extracted);
        }
        else {
            return this.next.extract(method);
        }
    };
    return RsaVerificationKeyExtractor;
}(DidVerificationKeyExtractor));
var EcdsaSecp256k1VerificationKeyExtractor = /** @class */ (function (_super) {
    __extends(EcdsaSecp256k1VerificationKeyExtractor, _super);
    function EcdsaSecp256k1VerificationKeyExtractor() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    EcdsaSecp256k1VerificationKeyExtractor.prototype.extract = function (method) {
        if (!method || !method.id || !method.type)
            throw new Error(exports.ERRORS.NO_MATCHING_PUBLIC_KEY);
        if (this.names.includes(method.type.toUpperCase())) {
            var extracted = {
                id: method.id,
                kty: globals_1.KTYS.EC,
                alg: globals_1.ALGORITHMS.ES256K,
                format: globals_1.KEY_FORMATS.HEX,
                publicKey: ''
            };
            return getVerificationKeyFromDifferentFormats(method, extracted);
        }
        else {
            return this.next.extract(method);
        }
    };
    return EcdsaSecp256k1VerificationKeyExtractor;
}(DidVerificationKeyExtractor));
var EcdsaSecp256r1VerificationKey2019Extractor = /** @class */ (function (_super) {
    __extends(EcdsaSecp256r1VerificationKey2019Extractor, _super);
    function EcdsaSecp256r1VerificationKey2019Extractor() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    EcdsaSecp256r1VerificationKey2019Extractor.prototype.extract = function (method) {
        if (!method || !method.id || !method.type)
            throw new Error(exports.ERRORS.NO_MATCHING_PUBLIC_KEY);
        if (this.names.includes(method.type.toUpperCase())) {
            var extracted = {
                id: method.id,
                kty: globals_1.KTYS.EC,
                alg: globals_1.ALGORITHMS.ES256,
                format: globals_1.KEY_FORMATS.HEX,
                publicKey: ''
            };
            return getVerificationKeyFromDifferentFormats(method, extracted);
        }
        else {
            return this.next.extract(method);
        }
    };
    return EcdsaSecp256r1VerificationKey2019Extractor;
}(DidVerificationKeyExtractor));
var EcdsaSecp256k1RecoveryMethod2020Extractor = /** @class */ (function (_super) {
    __extends(EcdsaSecp256k1RecoveryMethod2020Extractor, _super);
    function EcdsaSecp256k1RecoveryMethod2020Extractor() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    EcdsaSecp256k1RecoveryMethod2020Extractor.prototype.extract = function (method) {
        if (!method || !method.id || !method.type)
            throw new Error(exports.ERRORS.NO_MATCHING_PUBLIC_KEY);
        if (this.names.includes(method.type.toUpperCase()) || method.ethereumAddress) {
            var extracted = {
                id: method.id,
                kty: globals_1.KTYS.EC,
                alg: globals_1.ALGORITHMS["ES256K-R"],
                format: globals_1.KEY_FORMATS.HEX,
                publicKey: ''
            };
            return getVerificationKeyFromDifferentFormats(method, extracted);
        }
        else {
            return this.next.extract(method);
        }
    };
    return EcdsaSecp256k1RecoveryMethod2020Extractor;
}(DidVerificationKeyExtractor));
var UniversalDidPublicKeyExtractor = /** @class */ (function (_super) {
    __extends(UniversalDidPublicKeyExtractor, _super);
    function UniversalDidPublicKeyExtractor() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    UniversalDidPublicKeyExtractor.prototype.extract = function (method) {
        return this.next.extract(method);
    };
    return UniversalDidPublicKeyExtractor;
}(DidVerificationKeyExtractor));
// SchnorrSecp256k1VerificationKey2019
// X25519KeyAgreementKey2019
function getVerificationKeyFromDifferentFormats(method, holder) {
    if (!method || !holder)
        throw new Error(exports.ERRORS.UNSUPPORTED_KEY_FORMAT);
    if (method.publicKeyJwk) {
        holder.format = globals_1.KEY_FORMATS.JWK;
        holder.publicKey = method.publicKeyJwk;
    }
    else if (method.publicKeyHex) {
        holder.format = globals_1.KEY_FORMATS.HEX;
        holder.publicKey = method.publicKeyHex;
    }
    else if (method.publicKeyBase58) {
        holder.format = globals_1.KEY_FORMATS.BASE58;
        holder.publicKey = method.publicKeyBase58;
    }
    else if (method.publicKeyBase64) {
        holder.format = globals_1.KEY_FORMATS.BASE64;
        holder.publicKey = method.publicKeyBase64;
    }
    else if (method.publicKeyPem) {
        holder.format = globals_1.KEY_FORMATS.PKCS8_PEM;
        holder.publicKey = method.publicKeyPem;
    }
    else if (method.publicKeyPgp) {
        holder.format = globals_1.KEY_FORMATS.PKCS8_PEM;
        holder.publicKey = method.publicKeyGpg;
    }
    else if (method.ethereumAddress) {
        holder.format = globals_1.KEY_FORMATS.ETHEREUM_ADDRESS;
        holder.publicKey = toChecksumAddress(method.ethereumAddress);
    }
    else if (method.address) {
        holder.format = globals_1.KEY_FORMATS.ADDRESS;
        holder.publicKey = method.address;
    }
    else {
        throw new Error(exports.ERRORS.UNSUPPORTED_KEY_FORMAT);
    }
    if (holder.format && holder.publicKey) {
        return holder;
    }
    else {
        throw new Error(exports.ERRORS.UNSUPPORTED_KEY_FORMAT);
    }
}
var jwsVerificationKey2020Extractor = new JwsVerificationKey2020Extractor('JwsVerificationKey2020');
var ed25519VerificationKeyExtractor = new Ed25519VerificationKeyExtractor(['Ed25519VerificationKey2018', 'ED25519SignatureVerification'], jwsVerificationKey2020Extractor);
var gpgVerificationKey2020Extractor = new GpgVerificationKey2020Extractor('GpgVerificationKey2020', ed25519VerificationKeyExtractor);
var rsaVerificationKeyExtractor = new RsaVerificationKeyExtractor('RsaVerificationKey2018', gpgVerificationKey2020Extractor);
var ecdsaSecp256k1VerificationKeyExtractor = new EcdsaSecp256k1VerificationKeyExtractor(['EcdsaSecp256k1VerificationKey2019', 'Secp256k1VerificationKey2018', 'Secp256k1'], rsaVerificationKeyExtractor);
var ecdsaSecp256r1VerificationKey2019Extractor = new EcdsaSecp256r1VerificationKey2019Extractor('EcdsaSecp256r1VerificationKey2019', ecdsaSecp256k1VerificationKeyExtractor);
var ecdsaSecp256k1RecoveryMethod2020Extractor = new EcdsaSecp256k1RecoveryMethod2020Extractor('EcdsaSecp256k1RecoveryMethod2020', ecdsaSecp256r1VerificationKey2019Extractor);
exports.uniExtractor = new UniversalDidPublicKeyExtractor([], ecdsaSecp256k1RecoveryMethod2020Extractor);
//# sourceMappingURL=Identity.js.map