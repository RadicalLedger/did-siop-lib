import { RSAKey, ECKey, OKP } from './../src/core/JWKUtils';
import { ALGORITHMS, KEY_FORMATS } from './../src/core/globals';
import { sign, verify } from '../src/core/JWT';


const rs256TestResource = {
    jwtDecoded: {
        header: {
            alg: ALGORITHMS[ALGORITHMS.RS256],
            typ: 'JWT',
            kid: 'key_1',
        },
        payload: {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
        }
    },
    privateKey: RSAKey.fromPrivateKey(
        {
            "p": "yS5TAT-JqDgiDgUQeuW5n4XZRIiu9ADhckkzdYLu91RjV1mD0XkAS-3rdC--649pkZ0ZiNdHS9VgyNnhBoRcrlXwOPGY00MxHu89g93WQjP7-iGnzXfnzKaMQkhsNVMbBeAdJfn6ngheZPcsULJwWpdjSc7C8Zk4geZcf2xiyFk",
            "kty": "RSA",
            "q": "sIOHhxHez34ptuD3SiUtx4m3A9yBoHnEoEbVINK70cHxs1hm-QTd0ypfHzIMtiAR5lBlDcz5zSCn_-RxFL64XkTfs8wJ6pTMRjqsRmgC_xbD1BFiJ6j82GT_jzstHaW62nWnehB0rlaUztSgWhf8dUenc6NYLu1RgnMP-1MNWNM",
            "d": "YxWdqqbjCADCUF8SRNN3BitCQIqRJHbunGjNF3sHJVVuy1Rg_IadvTC8icdudHrnnQrBjqEx8lLBi7oXu2fiamfkrD0NZMK82s3R3DA62O4oHPD9_HpplIgyWfiVrDpuYSPf7-LNqWmVR28Njv9wGyFz6YlGttak_GJ1AH7MTUz1-Bn-rNsillWqu_0C7PmLUwwocpCjrvy8mvDv6bwDaTDsHhmId9NLfmR5zi3nAhNe4UC2Zuk_rlvLK65T38HU_uWWewNWNzLg7CmacImN666L8g3owvJ2w6NBc39Nghhj7XUqyCujroZVpXJilDpGQDobRRCE1ewUedfoGmqBcQ",
            "e": "AQAB",
            "use": "sig",
            "kid": "key_1",
            "qi": "AwYlmkohAhpMVHF_qB0gu1KS-INMn9l_kbDbLe8Td_qZffqHnepH8zTtVsDWTDQpL3mVgELx6ApBs4PjrcbkhD0th5wLmqKfELSOTdmo2tPAasyVXsvkhD3bxvnQ3FLo8bJi1Ff0uhy5wDsMXIwDnu6_zXi-TOU85P9exRzpibk",
            "dp": "t-eN3zU63Di8AL7masH3ZnkPvNOJwunPLQ73aHORiSxuR1o_4svO1poeQ66lw2Xs5jyLLAlHVm4vNEvfpXp30rIij5tizbS9gX7HZ_TxOMGWlPgREgWLMwwIaUsVB8X5jOxrGN0kGTSjPX6p1vbXOCjtjXnhwMME4dI4Og9VWbk",
            "alg": "RS256",
            "dq": "MMrq98dU0_6IAWmGchR85x-GW6bknjuKwtNRrtUR3hXCflT9gfB6cRjRWoo3QVD0IbovdPUoSC-ywOWg7J8bz9MyEz1fsFyZawBlBsFRsrnUQBbeDyCDZD3m9uzgt8VMNX84YGGUH20HjXTxLnZa7wBzpV-NzMsFMQ4laM-4bMk",
            "n": "irc2RuiQwgBwcJ3FilvWmdffu_9Uw1DTaULfU6zZMQowSqcANRCWbaLsa31vDLjLV8cpui50Ae3EX5asJdGJv9KVgBmDqmgekRh_UbefrA1TvwSBdb7yPaP1OlPPLluMEGVqPI1Q885ymAn1TcNTqq1QxUpeT8AETc3AX3rmQpCr14KO9iRi6u6sMfXC4IDTKUNWWXtm--rAAH366_FkFXyD_OfbgwXx_9dX2WyYKiIlCHrJMOSZlcd52HaUU1xMPxXuEUP3lAscamVfQPcWrT8DYmxY0zw6Sc5PqsTXzkBM2jkE-dcH315SUKGRzBj-D784ykkSynmD2TiEUc65Ww"
        }
    ),
    publicKey: RSAKey.fromPublicKey(
        {
            "kty": "RSA",
            "e": "AQAB",
            "use": "sig",
            "kid": "key_1",
            "alg": "RS256",
            "n": "irc2RuiQwgBwcJ3FilvWmdffu_9Uw1DTaULfU6zZMQowSqcANRCWbaLsa31vDLjLV8cpui50Ae3EX5asJdGJv9KVgBmDqmgekRh_UbefrA1TvwSBdb7yPaP1OlPPLluMEGVqPI1Q885ymAn1TcNTqq1QxUpeT8AETc3AX3rmQpCr14KO9iRi6u6sMfXC4IDTKUNWWXtm--rAAH366_FkFXyD_OfbgwXx_9dX2WyYKiIlCHrJMOSZlcd52HaUU1xMPxXuEUP3lAscamVfQPcWrT8DYmxY0zw6Sc5PqsTXzkBM2jkE-dcH315SUKGRzBj-D784ykkSynmD2TiEUc65Ww"
        }
    ),
    publicKeyWrong: RSAKey.fromPublicKey(
        {
            "kty": "RSA",
            "e": "AQAB",
            "use": "sig",
            "kid": "key_1",
            "alg": "RS256",
            "n": "y84D3oGLfX3Lv42800ImyxSlhzIgKkpPTiRebsMoubAVGhHV7INfqpU_Mq05B8kH_QLiRuuKfxGi1NsRyJYYld4CIrSPxCnWEyrL9sVvqOVuHT0nSo-BUcDNbr3GFTI5-7DOovo3n2YGfK208Xii9HUNDAvlTWODeDCbkfD5tsKRI6Hp_WfRCE5YZW4iHCxOlcSxCfEhLOoxomAnaJ_I8pRb2gAHL0jKRpIn8iMDFKhqdCeHkHRmXeiFLkbvTCnuNep0UJWzF0RxgsBNrhCUGtEe4Fw7YpBDCTDZBe7a4XFeUkLvcy5kMzvZyAIWUd1cXA8MtCzsuU7QwYiFQo9Eqw"
        }
    ),
}

const es256kTestResource = {
    jwtDecoded: {
        header: {
            alg: ALGORITHMS[ALGORITHMS.ES256K],
            typ: 'JWT',
            kid: 'key_1',
        },
        payload: {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
        }
    },
    privateKey: ECKey.fromPrivateKey(
        {
            "kty": "EC",
            "d": "qY02md1Z-mx7Bm99qjqaESCCE8PMpq8VWl3Kla9NexI",
            "use": "sig",
            "crv": "secp256k1",
            "kid": "key_1",
            "x": "fGyWU7xBqgKtBsVjAesZUC1PZhgdpZiV26DGHZ4BV5g",
            "y": "eBxt2i2koNKYqNNI7hTLU0qpsBRKZifw4kaU2RdntQk",
            "alg": "ES256K"
        }
    ),
    publicKey: ECKey.fromPublicKey(
        {
            "kty": "EC",
            "use": "sig",
            "crv": "secp256k1",
            "kid": "key_1",
            "x": "fGyWU7xBqgKtBsVjAesZUC1PZhgdpZiV26DGHZ4BV5g",
            "y": "eBxt2i2koNKYqNNI7hTLU0qpsBRKZifw4kaU2RdntQk",
            "alg": "ES256K"
        }
    ),
    publicKeyWrong: ECKey.fromPublicKey(
        {
            "kty": "EC",
            "use": "sig",
            "crv": "secp256k1",
            "kid": "key_1",
            "x": "Y4xeLjurYuJdXvGWegB3KDLmbU2t0yEE6SvyKvtyARU",
            "y": "V449HpYu8nAxwFoZH8TXr7Ofat5CnV1F557rSZboZp0",
            "alg": "ES256K"
        }
    ),

}

const es256kRecoverableResources = {
    jwtDecoded: {
        header: {
            alg: ALGORITHMS[ALGORITHMS["ES256K-R"]],
            typ: 'JWT',
            kid: 'key_1',
        },
        payload: {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
        }
    },
    privateKey: 'CE438802C1F0B6F12BC6E686F372D7D495BC5AA634134B4A7EA4603CB25F0964',
    publicKey: '0xB07Ead9717b44B6cF439c474362b9B0877CBBF83',
    publicKeyWrong: '0428c0da3e1c15e84876625d366eab8dd20c84288bcf6a71a0699209fc646dcfeb4633d7eff3dc63be7d7ada54fcb63cd603e5ac0a1382de19a73487dbc8e177e9',

}

const edDsaTestResources = {
    jwtDecoded: {
        header: {
            alg: ALGORITHMS[ALGORITHMS.EdDSA],
            typ: 'JWT',
            kid: 'key_1',
        },
        payload: {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
        }
    },
    privateKey: OKP.fromPrivateKey(
        {
            "kty": "OKP",
            "d": "V_KISRBGjffxWgpY6Kz2P9E1V-HPoJMww0CTcMzirYE",
            "use": "sig",
            "crv": "Ed25519",
            "kid": "key_1",
            "x": "kOx25WJpXq5yCv5-rGT15IRX-_Gg4nJ5wqqR_6YaDi8",
            "alg": "EdDSA"
        }
    ),
    publicKey: OKP.fromPublicKey(
        {
            "kty": "OKP",
            "use": "sig",
            "crv": "Ed25519",
            "kid": "key_1",
            "x": "kOx25WJpXq5yCv5-rGT15IRX-_Gg4nJ5wqqR_6YaDi8",
            "alg": "EdDSA"
        }
    ),
    publicKeyWrong: OKP.fromPublicKey(
        {
            "kty": "OKP",
            "use": "sig",
            "crv": "Ed25519",
            "kid": "key_1",
            "x": "RcPqPlTgM4NdeXCcaSIcZEePIvASAHvXQ6ZEls5rDnA",
            "alg": "EdDSA"
        }
    ),

}

describe('JWT functions', function() {
    test('JWT signing and verification RS256', async () => {
        let jwt = sign(rs256TestResource.jwtDecoded, {
            key: rs256TestResource.privateKey.exportKey(KEY_FORMATS.PKCS8_PEM),
            kid: rs256TestResource.jwtDecoded.header.kid,
            alg: ALGORITHMS.RS256,
            format: KEY_FORMATS.PKCS8_PEM
        });
        let validity = verify(jwt, {
            key: rs256TestResource.publicKey.exportKey(KEY_FORMATS.PKCS1_PEM),
            kid: rs256TestResource.jwtDecoded.header.kid,
            alg: ALGORITHMS.RS256,
            format: KEY_FORMATS.PKCS1_PEM
        });
        expect(validity).toBeTruthy();
        validity = verify(jwt, {
            key: rs256TestResource.publicKeyWrong.exportKey(KEY_FORMATS.PKCS1_PEM),
            kid: rs256TestResource.jwtDecoded.header.kid,
            alg: ALGORITHMS.RS256,
            format: KEY_FORMATS.PKCS1_PEM
        });
        expect(validity).toBeFalsy();
    });
    test('JWT signing and verification ES256K', async () => {
        let jwt = sign(es256kTestResource.jwtDecoded, {
            key: es256kTestResource.privateKey.exportKey(KEY_FORMATS.HEX),
            kid: es256kTestResource.jwtDecoded.header.kid,
            alg: ALGORITHMS.ES256K,
            format: KEY_FORMATS.HEX
        });
        let validity = verify(jwt, {
            key: es256kTestResource.publicKey.exportKey(KEY_FORMATS.HEX),
            kid: es256kTestResource.jwtDecoded.header.kid,
            alg: ALGORITHMS.ES256K,
            format: KEY_FORMATS.HEX
        });
        expect(validity).toBeTruthy();
        validity = verify(jwt, {
            key: es256kTestResource.publicKeyWrong.exportKey(KEY_FORMATS.HEX),
            kid: es256kTestResource.jwtDecoded.header.kid,
            alg: ALGORITHMS.ES256K,
            format: KEY_FORMATS.HEX
        });
        expect(validity).toBeFalsy();
    }),
    test('JWT signing and verification ES256K-R', async () => {
        let jwt = sign(es256kRecoverableResources.jwtDecoded, {
            key: es256kRecoverableResources.privateKey,
            kid: es256kRecoverableResources.jwtDecoded.header.kid,
            alg: ALGORITHMS["ES256K-R"],
            format: KEY_FORMATS.HEX
        });
        let validity = verify(jwt, {
            key: es256kRecoverableResources.publicKey,
            kid: es256kRecoverableResources.jwtDecoded.header.kid,
            alg: ALGORITHMS["ES256K-R"],
            format: KEY_FORMATS.HEX
        });
        expect(validity).toBeTruthy();
        validity = verify(jwt, {
            key: es256kRecoverableResources.publicKeyWrong,
            kid: es256kRecoverableResources.jwtDecoded.header.kid,
            alg: ALGORITHMS["ES256K-R"],
            format: KEY_FORMATS.HEX
        });
        expect(validity).toBeFalsy();
    })
    test('JWT signing and verification EdDSA', async () => {
        let jwt = sign(edDsaTestResources.jwtDecoded, {
            key: edDsaTestResources.privateKey.exportKey(KEY_FORMATS.HEX),
            kid: edDsaTestResources.jwtDecoded.header.kid,
            alg: ALGORITHMS.EdDSA,
            format: KEY_FORMATS.HEX
        });
        let validity = verify(jwt, {
            key: edDsaTestResources.publicKey.exportKey(KEY_FORMATS.HEX),
            kid: edDsaTestResources.jwtDecoded.header.kid,
            alg: ALGORITHMS.EdDSA,
            format: KEY_FORMATS.HEX
        });
        expect(validity).toBeTruthy();
        validity = verify(jwt, {
            key: edDsaTestResources.publicKeyWrong.exportKey(KEY_FORMATS.HEX),
            kid: edDsaTestResources.jwtDecoded.header.kid,
            alg: ALGORITHMS.EdDSA,
            format: KEY_FORMATS.HEX
        });
        expect(validity).toBeFalsy();
    })
})