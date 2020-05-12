"use strict";
exports.__esModule = true;
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
//# sourceMappingURL=Utils.js.map