import { sign } from '../../src/core/jwt';
import { JWTObject, SigningInfo } from '../../src/core/jwt';

const jwtGoodDecoded = {
    header: {
        typ: 'JWT',
        alg: 'ES256K',
        kid: ''
    },
    payload: {
        iss: '',
        response_type: 'id_token',
        client_id: '',
        scope: 'openid',
        state: 'af0ifjsldkj',
        nonce: 'n-0S6_WzA2Mj',
        response_mode: 'form_post',
        redirect_uri: 'https://my.rp.com/cb',
        registration: {
            jwks_uri: 'https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks',
            id_token_signed_response_alg: ['ES256K', 'ES256K-R', 'EdDSA', 'RS256']
        }
    }
};

export const checkParamsOfGoodDecoded = {
    redirect_uri: 'https://my.rp.com/cb',
    nonce: 'n-0S6_WzA2Mj',
    validBefore: 30000,
    isExpirable: true
};

export const claims = {
    good: {
        id_token: {
            email: null
        },
        vp_token: {
            presentation_definition: {
                id: 'vp token example',
                input_descriptors: [
                    {
                        id: 'id card credential',
                        format: {
                            ldp_vc: {
                                proof_type: ['Ed25519Signature2018']
                            }
                        },
                        constraints: {
                            fields: [
                                {
                                    path: ['$.type'],
                                    filter: {
                                        type: 'string',
                                        pattern: 'IDCardCredential'
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }
    },
    bad: {
        id_token: {
            email: null
        },
        vp_token: {}
    }
};

export const tokenData = {
    good: {
        singleVP: {
            id_token: {
                iss: 'https://self-issued.me/v2',
                aud: 'https://book.itsourweb.org:3000/client_api/authresp/uhn',
                iat: 1615910538,
                exp: 1615911138,
                sub: 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs',
                sub_jwk: {
                    kty: 'RSA',
                    n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx...DKgw',
                    e: 'AQAB'
                },
                auth_time: 1615910535,
                nonce: '960848874',
                _vp_token: {
                    presentation_submission: {
                        id: 'Selective disclosure example presentation',
                        definition_id: 'Selective disclosure example',
                        descriptor_map: [
                            {
                                id: 'ID Card with constraints',
                                format: 'ldp_vp',
                                path: '$',
                                path_nested: {
                                    format: 'ldp_vc',
                                    path: '$.verifiableCredential[0]'
                                }
                            }
                        ]
                    }
                }
            },
            vp_token: {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiablePresentation'],
                verifiableCredential: [
                    {
                        '@context': [
                            'https://www.w3.org/2018/credentials/v1',
                            'https://www.w3.org/2018/credentials/examples/v1'
                        ],
                        id: 'https://example.com/credentials/1872',
                        type: ['VerifiableCredential', 'IDCardCredential'],
                        issuer: {
                            id: 'did:example:issuer'
                        },
                        issuanceDate: '2010-01-01T19:23:24Z',
                        credentialSubject: {
                            given_name: 'Fredrik',
                            family_name: 'Str&#246;mberg',
                            birthdate: '1949-01-22'
                        },
                        proof: {
                            type: 'Ed25519Signature2018',
                            created: '2021-03-19T15:30:15Z',
                            jws: 'eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PT8yCqVjj5ZHD0W36zsBQ47oc3El07WGPWaLUuBTOT48IgKI5HDoiFUt9idChT_Zh5s8cF_2cSRWELuD8JQdBw',
                            proofPurpose: 'assertionMethod',
                            verificationMethod: 'did:example:issuer#keys-1'
                        }
                    }
                ],
                id: 'ebc6f1c2',
                holder: 'did:example:holder',
                proof: {
                    type: 'Ed25519Signature2018',
                    created: '2021-03-19T15:30:15Z',
                    challenge: 'n-0S6_WzA2Mj',
                    domain: 'https://client.example.org/cb',
                    jws: 'eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..GF5Z6TamgNE8QjE3RbiDOj3n_t25_1K7NVWMUASe_OEzQV63GaKdu235MCS3hIYvepcNdQ_ZOKpGNCf0vIAoDA',
                    proofPurpose: 'authentication',
                    verificationMethod: 'did:example:holder#key-1'
                }
            }
        }
    },
    bad: {
        singleVP: {
            id_token: {
                _vp_token: {}
            },
            vp_token: {
                test: {}
            }
        }
    }
};

export const getBasicJWT = function (kid: string, iss: string, did: string): JWTObject {
    let clonedJWT = JSON.parse(JSON.stringify(jwtGoodDecoded)); //To make a deep copy in an ugly way
    clonedJWT.header['kid'] = kid;
    clonedJWT.payload['iss'] = iss;
    clonedJWT.payload['client_id'] = did;

    return clonedJWT;
};

export const getModifiedJWT = function (
    jwt: JWTObject,
    isPayload: boolean,
    property: string,
    value?: any
) {
    let newJWT = JSON.parse(JSON.stringify(jwt));
    if (isPayload) {
        if (value === null) {
            delete newJWT.payload[property];
        } else {
            newJWT.payload[property] = value;
        }
    } else {
        if (!value) {
            delete newJWT.header[property];
        } else {
            newJWT.header[property] = value;
        }
    }
    return newJWT;
};

export const getModifiedJWTSigned = function (
    jwt: JWTObject,
    privateKey: SigningInfo,
    isPayload: boolean,
    property: string,
    value?: any
) {
    let newJwt = getModifiedJWT(jwt, isPayload, property, value);
    return sign(newJwt, privateKey);
};
