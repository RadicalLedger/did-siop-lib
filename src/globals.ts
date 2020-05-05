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