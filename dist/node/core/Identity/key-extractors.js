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
Object.defineProperty(exports, "__esModule", { value: true });
var commons_1 = require("./commons");
var globals_1 = require("../globals");
var Utils_1 = require("../Utils");
var toChecksumAddress = require('ethereum-checksum-address').toChecksumAddress;
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
        throw new Error(commons_1.ERRORS.UNSUPPORTED_PUBLIC_KEY_METHOD);
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
            throw new Error(commons_1.ERRORS.NO_MATCHING_PUBLIC_KEY);
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
                throw new Error(commons_1.ERRORS.UNSUPPORTED_PUBLIC_KEY_METHOD);
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
            throw new Error(commons_1.ERRORS.NO_MATCHING_PUBLIC_KEY);
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
            throw new Error(commons_1.ERRORS.NO_MATCHING_PUBLIC_KEY);
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
                throw new Error(commons_1.ERRORS.UNSUPPORTED_PUBLIC_KEY_METHOD);
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
            throw new Error(commons_1.ERRORS.NO_MATCHING_PUBLIC_KEY);
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
            throw new Error(commons_1.ERRORS.NO_MATCHING_PUBLIC_KEY);
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
            throw new Error(commons_1.ERRORS.NO_MATCHING_PUBLIC_KEY);
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
            throw new Error(commons_1.ERRORS.NO_MATCHING_PUBLIC_KEY);
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
        throw new Error(commons_1.ERRORS.UNSUPPORTED_KEY_FORMAT);
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
        throw new Error(commons_1.ERRORS.UNSUPPORTED_KEY_FORMAT);
    }
    if (holder.format && holder.publicKey) {
        return holder;
    }
    else {
        throw new Error(commons_1.ERRORS.UNSUPPORTED_KEY_FORMAT);
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
//# sourceMappingURL=key-extractors.js.map