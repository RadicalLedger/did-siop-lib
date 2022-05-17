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
export interface SiopMetadataSupported {
    authorization_endpoint: string;
    issuer: string;
    response_types: string[];
    scopes: string[];
    subject_types: string[];
    id_token_signing_alg_values: string[];
    request_object_signing_alg_values: string[];
    subject_syntax_types: string[];
    id_token_types: string[];
}
/**
 * This structure is used to specify what metadata would be used to communcate with the OP
 * If RP has metadata of OP acquired in and out-of-band method those will be used,
 * otherwise OP's static metadata would be used. Structure us initialised with SIOP_STATIC_METADATA_SUPPORTED
 * for the developer convenience
 */
export declare const SIOP_METADATA_SUPPORTED: SiopMetadataSupported;
export declare const CRYPTO_SUITES: {
    Ed25519VerificationKey2018: string;
    Ed25519VerificationKey2020: string;
};
