"use strict";
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
var globals_1 = require("./globals");
var base58 = __importStar(require("bs58"));
/**
 * @param {string} data - The string value needed to be padded
 * @param {number} [size = 64] - Required size (with padding). Default value is 64
 * @returns {string} - Left '0' padded string with the length specified by size param
 * @remarks This is a helper method used to add '0's to the start of a string
 * in order to increase its length to a specific value
 */
function leftpad(data, size) {
    if (size === void 0) { size = 64; }
    if (data.length === size)
        return data;
    return '0'.repeat(size - data.length) + data;
}
exports.leftpad = leftpad;
/**
 * @param {Key} privateKey - A Key object consisting of the private part of an asymmetric key pair
 * @param {Key} publicKey - A Key object consisting of the public part of an asymmetric key pair
 * @param {Signer} signer - A Signer object to test with the key pair
 * @param {Verifier} verifier - An object of related Verifier
 * @param {ALGORITHMS} algorithm - The algorithm to test with
 * @returns {boolean} - A boolean value indicating the validity of two Keys.
 * @remarks This is a helper function used to check if a certain private key relates to a certain public key
 */
function checkKeyPair(privateKey, publicKey, signer, verifier, algorithm) {
    var message = 'some test message';
    var signature = signer.sign(message, privateKey, algorithm);
    return verifier.verify(message, signature, publicKey, algorithm);
}
exports.checkKeyPair = checkKeyPair;
/**
 * @param {string} alg - Name of the algorithm as a string
 * @returns {ALGORITHMS} - Related enum type of the algorihm
 * @remarks This function is used to convert an algorithm name given as a string to a ALGORITHM value
 */
function getAlgorithm(alg) {
    return globals_1.ALGORITHMS[alg.toUpperCase()];
}
exports.getAlgorithm = getAlgorithm;
/**
 * @param {string} format - Name of the key format as a string
 * @returns {KEY_FORMATS} - Related enum type of the key format
 * @remarks This function is used to convert a key format given as a string to a KEY_FORMAT value
 */
function getKeyFormat(format) {
    return globals_1.KEY_FORMATS[format.toUpperCase()];
}
exports.getKeyFormat = getKeyFormat;
/**
 * @param {string} kty - Name of the key type as a string
 * @returns {KTYS} - Related enum type of the key type
 * @remarks This function is used to convert a key type name given as a string to a KTYS value
 */
function getKeyType(kty) {
    return globals_1.KTYS[kty.toUpperCase()];
}
exports.getKeyType = getKeyType;
function validJsonObject(obj) {
    var valid = true;
    if (obj) {
        try {
            if (JSON.parse(JSON.stringify(obj)) == undefined)
                valid = false;
        }
        catch (err) {
            valid = false;
        }
    }
    return valid;
}
exports.validJsonObject = validJsonObject;
function getBase58fromMultibase(key) {
    var x = base58.decode(key.slice(1)); // Drop z and convert to Uint8Array
    return base58.encode(x.subarray(2));
    ; // return Uint8Array after dropping Multibase Header bytes, encode in base58 and rerurn  
}
exports.getBase58fromMultibase = getBase58fromMultibase;
function isMultibasePvtKey(key) {
    try {
        var decoded = base58.decode(key.slice(1));
        if (key.charAt(0) == 'z' && // MULTIBASE_BASE58BTC_HEADER
            decoded[0] == 0x80 && // MULTICODEC_ED25519_PRIV_HEADER 1st byte
            decoded[1] == 0x26) // MULTICODEC_ED25519_PRIV_HEADER 2nd byte
            return true;
        else
            return false;
    }
    catch (err) {
        return false;
    }
}
exports.isMultibasePvtKey = isMultibasePvtKey;
//# sourceMappingURL=Utils.js.map