"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var ALGORITHMS;
(function (ALGORITHMS) {
    ALGORITHMS[ALGORITHMS["RS256"] = 0] = "RS256";
    ALGORITHMS[ALGORITHMS["RS384"] = 1] = "RS384";
    ALGORITHMS[ALGORITHMS["RS512"] = 2] = "RS512";
    ALGORITHMS[ALGORITHMS["PS256"] = 3] = "PS256";
    ALGORITHMS[ALGORITHMS["PS384"] = 4] = "PS384";
    ALGORITHMS[ALGORITHMS["PS512"] = 5] = "PS512";
    ALGORITHMS[ALGORITHMS["ES256"] = 6] = "ES256";
    ALGORITHMS[ALGORITHMS["ES384"] = 7] = "ES384";
    ALGORITHMS[ALGORITHMS["ES512"] = 8] = "ES512";
    ALGORITHMS[ALGORITHMS["ES256K"] = 9] = "ES256K";
    ALGORITHMS[ALGORITHMS["ES256K-R"] = 10] = "ES256K-R";
    ALGORITHMS[ALGORITHMS["EdDSA"] = 11] = "EdDSA";
})(ALGORITHMS = exports.ALGORITHMS || (exports.ALGORITHMS = {}));
exports.RSA_ALGORITHMS = [
    ALGORITHMS.RS256,
    ALGORITHMS.RS384,
    ALGORITHMS.RS512,
    ALGORITHMS.PS256,
    ALGORITHMS.PS256,
    ALGORITHMS.PS256,
];
exports.EC_ALGORITHMS = [
    ALGORITHMS.ES256,
    ALGORITHMS.ES384,
    ALGORITHMS.ES512,
    ALGORITHMS.ES256K,
];
exports.OKP_ALGORITHMS = [
    ALGORITHMS.EdDSA,
];
exports.SPECIAL_ALGORITHMS = [
    ALGORITHMS["ES256K-R"],
];
var KTYS;
(function (KTYS) {
    KTYS[KTYS["RSA"] = 0] = "RSA";
    KTYS[KTYS["EC"] = 1] = "EC";
    KTYS[KTYS["OKP"] = 2] = "OKP";
    KTYS[KTYS["oct"] = 3] = "oct";
})(KTYS = exports.KTYS || (exports.KTYS = {}));
var KEY_FORMATS;
(function (KEY_FORMATS) {
    KEY_FORMATS[KEY_FORMATS["PKCS8_PEM"] = 0] = "PKCS8_PEM";
    KEY_FORMATS[KEY_FORMATS["PKCS1_PEM"] = 1] = "PKCS1_PEM";
    KEY_FORMATS[KEY_FORMATS["HEX"] = 2] = "HEX";
    KEY_FORMATS[KEY_FORMATS["BASE58"] = 3] = "BASE58";
    KEY_FORMATS[KEY_FORMATS["BASE64"] = 4] = "BASE64";
    KEY_FORMATS[KEY_FORMATS["BASE64URL"] = 5] = "BASE64URL";
    KEY_FORMATS[KEY_FORMATS["ADDRESS"] = 6] = "ADDRESS";
    KEY_FORMATS[KEY_FORMATS["ETHEREUM_ADDRESS"] = 7] = "ETHEREUM_ADDRESS";
    KEY_FORMATS[KEY_FORMATS["JWK"] = 8] = "JWK";
})(KEY_FORMATS = exports.KEY_FORMATS || (exports.KEY_FORMATS = {}));
/**
 * Values to be used when dynamic metadata discovery is not possible
 * https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#name-static-self-issued-openid-p
 */
var SIOP_STATIC_METADATA_SUPPORTED = Object.freeze({
    authorization_endpoint: "openid:",
    issuer: "https://self-issued.me/v2",
    response_types_supported: ["id_token"],
    scopes_supported: ["openid", 'did_authn'],
    subject_types_supported: ["pairwise"],
    id_token_signing_alg_values_supported: ["ES256"],
    request_object_signing_alg_values_supported: ["ES256"],
    subject_syntax_types_supported: ["urn:ietf:params:oauth:jwk-thumbprint"],
    id_token_types_supported: ["subject_signed"]
});
/**
 * This structure is used to specify what metadata would be used to communcate with the OP
 * If RP has metadata of OP acquired in and out-of-band method those will be used,
 * otherwise OP's static metadata would be used. Structure us initialised with SIOP_STATIC_METADATA_SUPPORTED
 * for the developer convenience
 */
exports.SIOP_METADATA_SUPPORTED = {
    authorization_endpoint: SIOP_STATIC_METADATA_SUPPORTED.authorization_endpoint,
    issuer: SIOP_STATIC_METADATA_SUPPORTED.issuer,
    response_types: SIOP_STATIC_METADATA_SUPPORTED.response_types_supported,
    scopes: SIOP_STATIC_METADATA_SUPPORTED.scopes_supported,
    subject_types: SIOP_STATIC_METADATA_SUPPORTED.subject_types_supported,
    id_token_signing_alg_values: SIOP_STATIC_METADATA_SUPPORTED.id_token_signing_alg_values_supported,
    request_object_signing_alg_values: SIOP_STATIC_METADATA_SUPPORTED.request_object_signing_alg_values_supported,
    subject_syntax_types: SIOP_STATIC_METADATA_SUPPORTED.subject_syntax_types_supported,
    id_token_types: SIOP_STATIC_METADATA_SUPPORTED.id_token_types_supported
};
exports.CRYPTO_SUITES = {
    Ed25519VerificationKey2018: "@digitalbazaar/ed25519-verification-key-2018",
    Ed25519VerificationKey2020: "@digitalbazaar/ed25519-verification-key-2020"
};
//# sourceMappingURL=globals.js.map