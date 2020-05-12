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
exports.__esModule = true;
var crypto_1 = require("crypto");
var Utils_1 = require("./Utils");
var globals_1 = require("./globals");
var elliptic_1 = require("elliptic");
exports.ERRORS = Object.freeze({
    NO_PRIVATE_KEY: 'Not a private key',
    INVALID_ALGORITHM: 'Invalid algorithm'
});
var Signer = /** @class */ (function () {
    function Signer() {
    }
    return Signer;
}());
exports.Signer = Signer;
var RSASigner = /** @class */ (function (_super) {
    __extends(RSASigner, _super);
    function RSASigner() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    RSASigner.prototype.sign = function (message, key, algorithm) {
        if (key.isPrivate()) {
            var signer = void 0;
            var signerParams = {
                key: key.exportKey(globals_1.KEY_FORMATS.PKCS8_PEM)
            };
            switch (algorithm) {
                case globals_1.ALGORITHMS.RS256:
                    signer = crypto_1.createSign('RSA-SHA256');
                    break;
                case globals_1.ALGORITHMS.RS384:
                    signer = crypto_1.createSign('RSA-SHA384');
                    break;
                case globals_1.ALGORITHMS.RS512:
                    signer = crypto_1.createSign('RSA-SHA512');
                    break;
                case globals_1.ALGORITHMS.PS256: {
                    signer = crypto_1.createSign('RSA-SHA256');
                    signerParams.padding = crypto_1.constants.RSA_PKCS1_PSS_PADDING;
                    signerParams.saltLength = crypto_1.constants.RSA_PSS_SALTLEN_DIGEST;
                    break;
                }
                case globals_1.ALGORITHMS.PS384: {
                    signer = crypto_1.createSign('RSA-SHA384');
                    signerParams.padding = crypto_1.constants.RSA_PKCS1_PSS_PADDING;
                    signerParams.saltLength = crypto_1.constants.RSA_PSS_SALTLEN_DIGEST;
                    break;
                }
                case globals_1.ALGORITHMS.PS512: {
                    signer = crypto_1.createSign('RSA-SHA512');
                    signerParams.padding = crypto_1.constants.RSA_PKCS1_PSS_PADDING;
                    signerParams.saltLength = crypto_1.constants.RSA_PSS_SALTLEN_DIGEST;
                    break;
                }
                default: throw new Error(exports.ERRORS.INVALID_ALGORITHM);
            }
            return signer.update(message).sign(signerParams);
        }
        else {
            throw new Error(exports.ERRORS.NO_PRIVATE_KEY);
        }
    };
    return RSASigner;
}(Signer));
exports.RSASigner = RSASigner;
var ECSigner = /** @class */ (function (_super) {
    __extends(ECSigner, _super);
    function ECSigner() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    ECSigner.prototype.sign = function (message, key, algorithm) {
        if (key.isPrivate()) {
            var sha = void 0;
            var ec = void 0;
            switch (algorithm) {
                case globals_1.ALGORITHMS.ES256: {
                    sha = crypto_1.createHash('sha256');
                    ec = new elliptic_1.ec('p256');
                    break;
                }
                case globals_1.ALGORITHMS.ES384: {
                    sha = crypto_1.createHash('sha384');
                    ec = new elliptic_1.ec('p384');
                    break;
                }
                case globals_1.ALGORITHMS.ES512: {
                    sha = crypto_1.createHash('sha512');
                    ec = new elliptic_1.ec('p512');
                    break;
                }
                case globals_1.ALGORITHMS.ES256K: {
                    sha = crypto_1.createHash('sha256');
                    ec = new elliptic_1.ec('secp256k1');
                    break;
                }
                case globals_1.ALGORITHMS.EdDSA: {
                    sha = crypto_1.createHash('sha256');
                    ec = new elliptic_1.ec('ed25519');
                    break;
                }
                default: throw new Error(exports.ERRORS.INVALID_ALGORITHM);
            }
            var hash = sha.update(message).digest('hex');
            var ecKey = ec.keyFromPrivate(key.exportKey(globals_1.KEY_FORMATS.HEX));
            var ec256k_signature = ecKey.sign(hash);
            var signature = Buffer.alloc(64);
            Buffer.from(Utils_1.leftpad(ec256k_signature.r.toString('hex')), 'hex').copy(signature, 0);
            Buffer.from(Utils_1.leftpad(ec256k_signature.s.toString('hex')), 'hex').copy(signature, 32);
            return signature;
        }
        else {
            throw new Error(exports.ERRORS.NO_PRIVATE_KEY);
        }
    };
    return ECSigner;
}(Signer));
exports.ECSigner = ECSigner;
var OKPSigner = /** @class */ (function (_super) {
    __extends(OKPSigner, _super);
    function OKPSigner() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    OKPSigner.prototype.sign = function (message, key, algorithm) {
        if (key.isPrivate()) {
            var ed = void 0;
            switch (algorithm) {
                case globals_1.ALGORITHMS.EdDSA: {
                    ed = new elliptic_1.eddsa('ed25519');
                    break;
                }
                default: throw new Error(exports.ERRORS.INVALID_ALGORITHM);
            }
            var edKey = ed.keyFromSecret(key.exportKey(globals_1.KEY_FORMATS.HEX));
            var edDsa_signature = edKey.sign(Buffer.from(message));
            return Buffer.from(edDsa_signature.toHex(), 'hex');
        }
        else {
            throw new Error(exports.ERRORS.NO_PRIVATE_KEY);
        }
    };
    return OKPSigner;
}(Signer));
exports.OKPSigner = OKPSigner;
var ES256KRecoverableSigner = /** @class */ (function (_super) {
    __extends(ES256KRecoverableSigner, _super);
    function ES256KRecoverableSigner() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    ES256KRecoverableSigner.prototype.sign = function (message, key) {
        var keyHexString;
        if (typeof key === 'string') {
            keyHexString = key;
        }
        else {
            keyHexString = key.exportKey(globals_1.KEY_FORMATS.HEX);
        }
        var sha = crypto_1.createHash('sha256');
        var ec = new elliptic_1.ec('secp256k1');
        var hash = sha.update(message).digest('hex');
        var signingKey = ec.keyFromPrivate(keyHexString);
        var ec256k_signature = signingKey.sign(hash);
        var jose = Buffer.alloc(65);
        Buffer.from(Utils_1.leftpad(ec256k_signature.r.toString('hex')), 'hex').copy(jose, 0);
        Buffer.from(Utils_1.leftpad(ec256k_signature.s.toString('hex')), 'hex').copy(jose, 32);
        if (ec256k_signature.recoveryParam !== undefined && ec256k_signature.recoveryParam !== null)
            jose[64] = ec256k_signature.recoveryParam;
        return jose;
    };
    return ES256KRecoverableSigner;
}(Signer));
exports.ES256KRecoverableSigner = ES256KRecoverableSigner;
//# sourceMappingURL=Signers.js.map