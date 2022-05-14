export enum ALGORITHMS {
    'RS256',
    'RS384',
    'RS512', 
    'PS256',
    'PS384',
    'PS512',
    'ES256',
    'ES384',
    'ES512',
    'ES256K',
    'ES256K-R',
    'EdDSA',
}

export const RSA_ALGORITHMS = [
    ALGORITHMS.RS256,
    ALGORITHMS.RS384,
    ALGORITHMS.RS512,
    ALGORITHMS.PS256,
    ALGORITHMS.PS256,
    ALGORITHMS.PS256,
];

export const EC_ALGORITHMS = [
    ALGORITHMS.ES256,
    ALGORITHMS.ES384,
    ALGORITHMS.ES512,
    ALGORITHMS.ES256K,
];

export const OKP_ALGORITHMS = [
    ALGORITHMS.EdDSA,
];

export const SPECIAL_ALGORITHMS = [
    ALGORITHMS["ES256K-R"],
];

export enum KTYS{
    'RSA',
    'EC',
    'OKP',
    'oct',
}

export enum KEY_FORMATS {
    PKCS8_PEM,
    PKCS1_PEM,
    HEX,
    BASE58,
    BASE64,
    BASE64URL,
    ADDRESS,
    ETHEREUM_ADDRESS,
    JWK,
}


export const SIOP_DISCOVERY_METADATA_STATIC = {
    authorization_endpoint: "openid:",
    issuer: "https://self-issued.me/v2",
    response_types_supported: ["id_token"],
    scopes_supported: ["openid"],
    subject_types_supported: ["pairwise"],
    id_token_signing_alg_values_supported: ["ES256"],
    request_object_signing_alg_values_supported: ["ES256"],
    subject_syntax_types_supported: ["urn:ietf:params:oauth:jwk-thumbprint"],
    id_token_types_supported: ["subject_signed"]
}

export const CRYPTO_SUITES = {
    Ed25519VerificationKey2018 : "@digitalbazaar/ed25519-verification-key-2018",
    Ed25519VerificationKey2020 : "@digitalbazaar/ed25519-verification-key-2020"    
}
