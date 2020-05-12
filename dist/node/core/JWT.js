"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
exports.__esModule = true;
var base64url_1 = __importDefault(require("base64url"));
var globals_1 = require("./globals");
var Signers_1 = require("./Signers");
var Verifiers_1 = require("./Verifiers");
exports.ERRORS = Object.freeze({
    UNSUPPORTED_ALGORITHM: 'Unsupported algorithm',
    INVALID_JWT: 'Invalid JWT',
    INVALID_SIGNATURE: 'Invalid signature'
});
function sign(jwtObject, key) {
    var unsigned = base64url_1["default"].encode(JSON.stringify(jwtObject.header)) + '.' + base64url_1["default"].encode(JSON.stringify(jwtObject.payload));
    var algorithm = globals_1.ALGORITHMS[jwtObject.header.alg];
    var signer = undefined;
    if (globals_1.RSA_ALGORITHMS.includes(algorithm)) {
        signer = new Signers_1.RSASigner();
    }
    else if (globals_1.EC_ALGORITHMS.includes(algorithm)) {
        signer = new Signers_1.ECSigner();
    }
    else if (globals_1.OKP_ALGORITHMS.includes(algorithm)) {
        signer = new Signers_1.OKPSigner();
    }
    else if (globals_1.SPECIAL_ALGORITHMS.includes(algorithm)) {
        switch (algorithm) {
            case globals_1.ALGORITHMS["ES256K-R"]:
                signer = new Signers_1.ES256KRecoverableSigner();
                break;
        }
    }
    if (signer) {
        var signature = signer.sign(unsigned, key, algorithm);
        return unsigned + '.' + base64url_1["default"].encode(signature);
    }
    else {
        throw new Error(exports.ERRORS.UNSUPPORTED_ALGORITHM);
    }
}
exports.sign = sign;
function verify(jwt, key) {
    var decoded = decodeJWT(jwt);
    var algorithm = globals_1.ALGORITHMS[decoded.header.alg];
    var verifier = undefined;
    if (globals_1.RSA_ALGORITHMS.includes(algorithm)) {
        verifier = new Verifiers_1.RSAVerifier();
    }
    else if (globals_1.EC_ALGORITHMS.includes(algorithm)) {
        verifier = new Verifiers_1.ECVerifier();
    }
    else if (globals_1.OKP_ALGORITHMS.includes(algorithm)) {
        verifier = new Verifiers_1.OKPVerifier();
    }
    else if (globals_1.SPECIAL_ALGORITHMS.includes(algorithm)) {
        switch (algorithm) {
            case globals_1.ALGORITHMS["ES256K-R"]:
                verifier = new Verifiers_1.ES256KRecoverableVerifier();
                break;
        }
    }
    if (verifier) {
        return verifier.verify(decoded.signed, decoded.signature, key, algorithm);
    }
    else {
        throw new Error(exports.ERRORS.INVALID_SIGNATURE);
    }
}
exports.verify = verify;
function decodeJWT(jwt) {
    try {
        var decodedHeader = JSON.parse(base64url_1["default"].decode(jwt.split('.')[0]));
        var payload = JSON.parse(base64url_1["default"].decode(jwt.split('.')[1]));
        var signature = base64url_1["default"].toBuffer(jwt.split('.')[2]);
        return {
            header: {
                typ: decodedHeader.typ,
                alg: decodedHeader.alg,
                kid: decodedHeader.kid
            },
            payload: payload,
            signed: jwt.split('.')[0] + '.' + jwt.split('.')[1],
            signature: signature
        };
    }
    catch (err) {
        throw new Error(exports.ERRORS.INVALID_JWT);
    }
}
//# sourceMappingURL=JWT.js.map