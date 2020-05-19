"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var JWKUtils_1 = require("./JWKUtils");
var base64url_1 = __importDefault(require("base64url"));
var globals_1 = require("./globals");
var Signers_1 = require("./Signers");
var Verifiers_1 = require("./Verifiers");
exports.ERRORS = Object.freeze({
    UNSUPPORTED_ALGORITHM: 'Unsupported algorithm',
    ALGORITHM_MISMATCH: 'Algorithm in jwt header does not match alg in signing info',
    INVALID_JWT: 'Invalid JWT',
    INVALID_SIGNATURE: 'Invalid signature',
});
function sign(jwtObject, signingInfo) {
    var unsigned = base64url_1.default.encode(JSON.stringify(jwtObject.header)) + '.' + base64url_1.default.encode(JSON.stringify(jwtObject.payload));
    var algorithm = globals_1.ALGORITHMS[jwtObject.header.alg];
    if (algorithm !== signingInfo.alg)
        throw new Error(exports.ERRORS.ALGORITHM_MISMATCH);
    var signer;
    var key;
    if (globals_1.RSA_ALGORITHMS.includes(algorithm)) {
        signer = new Signers_1.RSASigner();
        key = JWKUtils_1.RSAKey.fromKey({
            key: signingInfo.key,
            kid: signingInfo.kid,
            use: 'sig',
            kty: 'RSA',
            alg: jwtObject.header.alg,
            format: signingInfo.format,
            isPrivate: true,
        });
    }
    else if (globals_1.EC_ALGORITHMS.includes(algorithm)) {
        signer = new Signers_1.ECSigner();
        key = JWKUtils_1.ECKey.fromKey({
            key: signingInfo.key,
            kid: signingInfo.kid,
            use: 'sig',
            kty: 'EC',
            alg: jwtObject.header.alg,
            format: signingInfo.format,
            isPrivate: true,
        });
    }
    else if (globals_1.OKP_ALGORITHMS.includes(algorithm)) {
        signer = new Signers_1.OKPSigner();
        key = JWKUtils_1.OKP.fromKey({
            key: signingInfo.key,
            kid: signingInfo.kid,
            use: 'sig',
            kty: 'OKP',
            alg: jwtObject.header.alg,
            format: signingInfo.format,
            isPrivate: true,
        });
    }
    else if (globals_1.SPECIAL_ALGORITHMS.includes(algorithm)) {
        switch (algorithm) {
            case globals_1.ALGORITHMS["ES256K-R"]: {
                signer = new Signers_1.ES256KRecoverableSigner();
                key = signingInfo.key;
                break;
            }
        }
    }
    if (signer && key) {
        var signature = signer.sign(unsigned, key, algorithm);
        return unsigned + '.' + base64url_1.default.encode(signature);
    }
    else {
        throw new Error(exports.ERRORS.UNSUPPORTED_ALGORITHM);
    }
}
exports.sign = sign;
function verify(jwt, signingInfo) {
    var decoded = decodeJWT(jwt);
    var algorithm = globals_1.ALGORITHMS[decoded.header.alg];
    if (algorithm !== signingInfo.alg)
        throw new Error(exports.ERRORS.ALGORITHM_MISMATCH);
    var verifier;
    var key;
    if (globals_1.RSA_ALGORITHMS.includes(algorithm)) {
        verifier = new Verifiers_1.RSAVerifier();
        key = JWKUtils_1.RSAKey.fromKey({
            key: signingInfo.key,
            kid: signingInfo.kid,
            use: 'sig',
            kty: 'RSA',
            alg: decoded.header.alg,
            format: signingInfo.format,
            isPrivate: false,
        });
    }
    else if (globals_1.EC_ALGORITHMS.includes(algorithm)) {
        verifier = new Verifiers_1.ECVerifier();
        key = JWKUtils_1.ECKey.fromKey({
            key: signingInfo.key,
            kid: signingInfo.kid,
            use: 'sig',
            kty: 'EC',
            alg: decoded.header.alg,
            format: signingInfo.format,
            isPrivate: false,
        });
    }
    else if (globals_1.OKP_ALGORITHMS.includes(algorithm)) {
        verifier = new Verifiers_1.OKPVerifier();
        key = JWKUtils_1.OKP.fromKey({
            key: signingInfo.key,
            kid: signingInfo.kid,
            use: 'sig',
            kty: 'OKP',
            alg: decoded.header.alg,
            format: signingInfo.format,
            isPrivate: false,
        });
    }
    else if (globals_1.SPECIAL_ALGORITHMS.includes(algorithm)) {
        switch (algorithm) {
            case globals_1.ALGORITHMS["ES256K-R"]: {
                verifier = new Verifiers_1.ES256KRecoverableVerifier();
                key = signingInfo.key;
                break;
            }
        }
    }
    if (verifier && key) {
        return verifier.verify(decoded.signed, decoded.signature, key, algorithm);
    }
    else {
        throw new Error(exports.ERRORS.INVALID_SIGNATURE);
    }
}
exports.verify = verify;
function decodeJWT(jwt) {
    try {
        var decodedHeader = JSON.parse(base64url_1.default.decode(jwt.split('.')[0]));
        var payload = JSON.parse(base64url_1.default.decode(jwt.split('.')[1]));
        var signature = base64url_1.default.toBuffer(jwt.split('.')[2]);
        return {
            header: {
                typ: decodedHeader.typ,
                alg: decodedHeader.alg,
                kid: decodedHeader.kid,
            },
            payload: payload,
            signed: jwt.split('.')[0] + '.' + jwt.split('.')[1],
            signature: signature,
        };
    }
    catch (err) {
        throw new Error(exports.ERRORS.INVALID_JWT);
    }
}
//# sourceMappingURL=JWT.js.map