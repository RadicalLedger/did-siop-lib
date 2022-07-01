export enum ALGORITHMS {
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
  "ES256K",
  "ES256K-R",
  "EdDSA",
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

export const OKP_ALGORITHMS = [ALGORITHMS.EdDSA];

export const SPECIAL_ALGORITHMS = [ALGORITHMS["ES256K-R"]];

export enum KTYS {
  "RSA",
  "EC",
  "OKP",
  "oct",
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

/**
 * Values to be used when dynamic metadata discovery is not possible
 * https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#name-static-self-issued-openid-p
 */
const SIOP_STATIC_METADATA_SUPPORTED = Object.freeze({
  authorization_endpoint: "openid:",
  issuer: "https://self-issued.me/v2",
  response_types_supported: ["id_token"],
  scopes_supported: ["openid", "did_authn"],
  subject_types_supported: ["pairwise"],
  id_token_signing_alg_values_supported: ["ES256"],
  request_object_signing_alg_values_supported: ["ES256"],
  subject_syntax_types_supported: ["urn:ietf:params:oauth:jwk-thumbprint"],
  id_token_types_supported: ["subject_signed"],
});

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

export const SIOP_METADATA_SUPPORTED: SiopMetadataSupported = {
  authorization_endpoint: SIOP_STATIC_METADATA_SUPPORTED.authorization_endpoint,
  issuer: SIOP_STATIC_METADATA_SUPPORTED.issuer,
  response_types: SIOP_STATIC_METADATA_SUPPORTED.response_types_supported,
  scopes: SIOP_STATIC_METADATA_SUPPORTED.scopes_supported,
  subject_types: SIOP_STATIC_METADATA_SUPPORTED.subject_types_supported,
  id_token_signing_alg_values:
    SIOP_STATIC_METADATA_SUPPORTED.id_token_signing_alg_values_supported,
  request_object_signing_alg_values:
    SIOP_STATIC_METADATA_SUPPORTED.request_object_signing_alg_values_supported,
  subject_syntax_types:
    SIOP_STATIC_METADATA_SUPPORTED.subject_syntax_types_supported,
  id_token_types: SIOP_STATIC_METADATA_SUPPORTED.id_token_types_supported,
};

export const CRYPTO_SUITES = {
  Ed25519VerificationKey2018: "@digitalbazaar/ed25519-verification-key-2018",
  Ed25519VerificationKey2020: "@digitalbazaar/ed25519-verification-key-2020",
};
