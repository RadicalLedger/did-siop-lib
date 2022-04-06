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
var globals_1 = require("./globals");
var crypto_1 = require("crypto");
var elliptic_1 = require("elliptic");
var publicKeyToAddress = require('ethereum-public-key-to-address');
exports.ERRORS = Object.freeze({
    NO_PRIVATE_KEY: 'Not a private key',
    INVALID_ALGORITHM: 'Invalid algorithm',
    INVALID_SIGNATURE: 'Invalid signature',
});
/**
 * @classdesc This abstract class defines the interface for classes used to verify cryptographically signed messages
 */
var Verifier = /** @class */ (function () {
    function Verifier() {
    }
    return Verifier;
}());
exports.Verifier = Verifier;
/**
 * @classdesc This class provides RSA signature verification
 * @extends {Verifier}
 */
var RSAVerifier = /** @class */ (function (_super) {
    __extends(RSAVerifier, _super);
    function RSAVerifier() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    /**
     * @param {string} msg - The message which needs to be verified
     * @param {Buffer} signature - The signature of the message
     * @param {RSAKey} key - An RSAKey object used for verification (Public Key)
     * @param {ALGORITHMS} algorithm - The algorithm used for the verification process. Must be one of RSA + SHA variant
     * @returns {boolean} - The result of the verification. Indicates whether the given signature matches the message.
     * @remarks This method will verify the message using selected algorithm and return the result.
     */
    RSAVerifier.prototype.verify = function (msg, signature, key, algorithm) {
        try {
            var verifier = void 0;
            var verifierParams = {
                key: key.exportKey(globals_1.KEY_FORMATS.PKCS8_PEM),
            };
            switch (algorithm) {
                case globals_1.ALGORITHMS.RS256:
                    verifier = crypto_1.createVerify('RSA-SHA256');
                    break;
                case globals_1.ALGORITHMS.RS384:
                    verifier = crypto_1.createVerify('RSA-SHA384');
                    break;
                case globals_1.ALGORITHMS.RS512:
                    verifier = crypto_1.createVerify('RSA-SHA512');
                    break;
                case globals_1.ALGORITHMS.PS256: {
                    verifier = crypto_1.createVerify('RSA-SHA256');
                    verifierParams.padding = crypto_1.constants.RSA_PKCS1_PSS_PADDING;
                    verifierParams.saltLength = crypto_1.constants.RSA_PSS_SALTLEN_DIGEST;
                    break;
                }
                case globals_1.ALGORITHMS.PS384: {
                    verifier = crypto_1.createVerify('RSA-SHA384');
                    verifierParams.padding = crypto_1.constants.RSA_PKCS1_PSS_PADDING;
                    verifierParams.saltLength = crypto_1.constants.RSA_PSS_SALTLEN_DIGEST;
                    break;
                }
                case globals_1.ALGORITHMS.PS512: {
                    verifier = crypto_1.createVerify('RSA-SHA512');
                    verifierParams.padding = crypto_1.constants.RSA_PKCS1_PSS_PADDING;
                    verifierParams.saltLength = crypto_1.constants.RSA_PSS_SALTLEN_DIGEST;
                    break;
                }
                default: throw new Error(exports.ERRORS.INVALID_ALGORITHM);
            }
            return verifier.update(msg).verify(verifierParams, signature);
        }
        catch (err) {
            throw new Error(exports.ERRORS.INVALID_SIGNATURE);
        }
    };
    return RSAVerifier;
}(Verifier));
exports.RSAVerifier = RSAVerifier;
/**
 * @classdesc This class provides Elliptic Curve signature verification
 * @extends {Verifier}
 */
var ECVerifier = /** @class */ (function (_super) {
    __extends(ECVerifier, _super);
    function ECVerifier() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    /**
     * @param {string} msg - The message which needs to be verified
     * @param {Buffer} signature - The signature of the message
     * @param {ECKey} key - An ECKey object used for verification (Public Key)
     * @param {ALGORITHMS} algorithm - The algorithm used for the verification process. Must be one of Curve variant + SHA variant
     * @returns {boolean} - The result of the verification. Indicates whether the given signature matches the message.
     * @remarks This method will verify the message using selected algorithm and return the result.
     */
    ECVerifier.prototype.verify = function (msg, signature, key, algorithm) {
        try {
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
            var hash = sha.update(msg).digest();
            if (signature.length !== 64)
                throw new Error(exports.ERRORS.INVALID_SIGNATURE);
            var signatureObj = {
                r: signature.slice(0, 32).toString('hex'),
                s: signature.slice(32, 64).toString('hex')
            };
            var ecKey = ec.keyFromPublic(key.exportKey(globals_1.KEY_FORMATS.HEX), 'hex');
            return ecKey.verify(hash, signatureObj);
        }
        catch (err) {
            throw new Error(exports.ERRORS.INVALID_SIGNATURE);
        }
    };
    return ECVerifier;
}(Verifier));
exports.ECVerifier = ECVerifier;
/**
 * @classdesc This class provides Edwards Curve signature verification
 * @extends {Verifier}
 */
var OKPVerifier = /** @class */ (function (_super) {
    __extends(OKPVerifier, _super);
    function OKPVerifier() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    /**
     * @param {string} msg - The message which needs to be verified
     * @param {Buffer} signature - The signature of the message
     * @param {OKP} key - An OKP object used for verification (Public Key)
     * @param {ALGORITHMS} algorithm - The algorithm used for the verification process. (ed25519)
     * @returns {boolean} - The result of the verification. Indicates whether the given signature matches the message.
     * @remarks This method will verify the message using selected algorithm (ed25519) and return the result.
     */
    OKPVerifier.prototype.verify = function (msg, signature, key, algorithm) {
        try {
            var ed = void 0;
            switch (algorithm) {
                case globals_1.ALGORITHMS.EdDSA: {
                    ed = new elliptic_1.eddsa('ed25519');
                    break;
                }
                default: throw new Error(exports.ERRORS.INVALID_ALGORITHM);
            }
            var edKey = ed.keyFromPublic(key.exportKey(globals_1.KEY_FORMATS.HEX));
            return edKey.verify(Buffer.from(msg), signature.toString('hex'));
        }
        catch (err) {
            throw new Error(exports.ERRORS.INVALID_SIGNATURE);
        }
    };
    return OKPVerifier;
}(Verifier));
exports.OKPVerifier = OKPVerifier;
/**
 * @classdesc This class provides signature verification using ES256K-R algorithm
 * @extends {Verifier}
 */
var ES256KRecoverableVerifier = /** @class */ (function (_super) {
    __extends(ES256KRecoverableVerifier, _super);
    function ES256KRecoverableVerifier() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    /**
     * @param {string} msg - The message which needs to be verified
     * @param {Buffer} signature - The signature of the message
     * @param {ECKey | string} key - Public Key either as an ECKey or a hex string
     * @returns {boolean} - The result of the verification. Indicates whether the given signature matches the message.
     * @remarks This method first checks whether the key is a string. If it is not then it will be converted to string
     * using ECKey.exportKey(). This class supports only one algorithm which is curve secp256k1 recoverable method.
     */
    ES256KRecoverableVerifier.prototype.verify = function (msg, signature, key) {
        var keyHexString;
        if (typeof key === 'string') {
            keyHexString = key;
        }
        else {
            keyHexString = key.exportKey(globals_1.KEY_FORMATS.HEX);
        }
        var sha = crypto_1.createHash('sha256');
        var ec = new elliptic_1.ec('secp256k1');
        var hash = sha.update(msg).digest();
        if (signature.length !== 65)
            throw new Error(exports.ERRORS.INVALID_SIGNATURE);
        var signatureObj = {
            r: signature.slice(0, 32).toString('hex'),
            s: signature.slice(32, 64).toString('hex'),
        };
        var recoveredKey = ec.recoverPubKey(hash, signatureObj, signature[64]);
        return (recoveredKey.encode('hex') === keyHexString ||
            recoveredKey.encode('hex', true) === keyHexString ||
            publicKeyToAddress(recoveredKey.encode('hex')) === keyHexString);
    };
    return ES256KRecoverableVerifier;
}(Verifier));
exports.ES256KRecoverableVerifier = ES256KRecoverableVerifier;
//# sourceMappingURL=Verifiers.js.map