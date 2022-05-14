export declare enum ALGORITHMS {
    'RS256' = 0,
    'RS384' = 1,
    'RS512' = 2,
    'PS256' = 3,
    'PS384' = 4,
    'PS512' = 5,
    'ES256' = 6,
    'ES384' = 7,
    'ES512' = 8,
    'ES256K' = 9,
    'ES256K-R' = 10,
    'EdDSA' = 11
}
export declare const RSA_ALGORITHMS: ALGORITHMS[];
export declare const EC_ALGORITHMS: ALGORITHMS[];
export declare const OKP_ALGORITHMS: ALGORITHMS[];
export declare const SPECIAL_ALGORITHMS: ALGORITHMS[];
export declare enum KTYS {
    'RSA' = 0,
    'EC' = 1,
    'OKP' = 2,
    'oct' = 3
}
export declare enum KEY_FORMATS {
    PKCS8_PEM = 0,
    PKCS1_PEM = 1,
    HEX = 2,
    BASE58 = 3,
    BASE64 = 4,
    BASE64URL = 5,
    ADDRESS = 6,
    ETHEREUM_ADDRESS = 7,
    JWK = 8
}
export declare const SIOP_DISCOVERY_METADATA_STATIC: {
    authorization_endpoint: string;
    issuer: string;
    response_types_supported: string[];
    scopes_supported: string[];
    subject_types_supported: string[];
    id_token_signing_alg_values_supported: string[];
    request_object_signing_alg_values_supported: string[];
    subject_syntax_types_supported: string[];
    id_token_types_supported: string[];
};
export declare const CRYPTO_SUITES: {
    Ed25519VerificationKey2018: string;
    Ed25519VerificationKey2020: string;
};
