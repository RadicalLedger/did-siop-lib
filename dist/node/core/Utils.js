"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var globals_1 = require("./globals");
function leftpad(data, size) {
    if (size === void 0) { size = 64; }
    if (data.length === size)
        return data;
    return '0'.repeat(size - data.length) + data;
}
exports.leftpad = leftpad;
function checkKeyPair(privateKey, publicKey, signer, verifier, algorithm) {
    var message = 'some test message';
    var signature = signer.sign(message, privateKey, algorithm);
    return verifier.verify(message, signature, publicKey, algorithm);
}
exports.checkKeyPair = checkKeyPair;
function getAlgorithm(alg) {
    return globals_1.ALGORITHMS[alg.toUpperCase()];
}
exports.getAlgorithm = getAlgorithm;
function getKeyFormat(format) {
    return globals_1.KEY_FORMATS[format.toUpperCase()];
}
exports.getKeyFormat = getKeyFormat;
//# sourceMappingURL=Utils.js.map