import { sign, verify, ALGORITHMS, ERRORS } from '../src/JWT'
import { JWK } from 'jose';

const rs256TestResource = {
    jwtDecoded: {
        header: {
            "alg": "RS256",
            "typ": "JWT"
        },
        payload: {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
        }
    },
    kid: 'key_1',
    privateKey: JWK.asKey(
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
    publicKey: JWK.asKey(
        {
            "kty": "RSA",
            "e": "AQAB",
            "use": "sig",
            "kid": "key_1",
            "alg": "RS256",
            "n": "irc2RuiQwgBwcJ3FilvWmdffu_9Uw1DTaULfU6zZMQowSqcANRCWbaLsa31vDLjLV8cpui50Ae3EX5asJdGJv9KVgBmDqmgekRh_UbefrA1TvwSBdb7yPaP1OlPPLluMEGVqPI1Q885ymAn1TcNTqq1QxUpeT8AETc3AX3rmQpCr14KO9iRi6u6sMfXC4IDTKUNWWXtm--rAAH366_FkFXyD_OfbgwXx_9dX2WyYKiIlCHrJMOSZlcd52HaUU1xMPxXuEUP3lAscamVfQPcWrT8DYmxY0zw6Sc5PqsTXzkBM2jkE-dcH315SUKGRzBj-D784ykkSynmD2TiEUc65Ww"
        }
    ),
    publicKeyWrong: JWK.asKey(
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
            "alg": "ES256K",
            "typ": "JWT"
        },
        payload: {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
        }
    },
    kid: 'key_1',
    privateKey: JWK.asKey(
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
    publicKey: JWK.asKey(
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
    publicKeyWrong: JWK.asKey(
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
            "alg": "ES256K-R",
            "typ": "JWT"
        },
        payload: {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
        }
    },
    kid: 'key_1',
    privateKey: 'CE438802C1F0B6F12BC6E686F372D7D495BC5AA634134B4A7EA4603CB25F0964',
    publicKey: '0xB07Ead9717b44B6cF439c474362b9B0877CBBF83',
    publicKeyWrong: '0428c0da3e1c15e84876625d366eab8dd20c84288bcf6a71a0699209fc646dcfeb4633d7eff3dc63be7d7ada54fcb63cd603e5ac0a1382de19a73487dbc8e177e9',

}

const edDsaTestResources = {
    jwtDecoded: {
        header: {
            "alg": "EdDSA",
            "typ": "JWT"
        },
        payload: {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
        }
    },
    kid: 'key_1',
    privateKey: JWK.asKey(
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
    publicKey: JWK.asKey(
        {
            "kty": "OKP",
            "use": "sig",
            "crv": "Ed25519",
            "kid": "key_1",
            "x": "kOx25WJpXq5yCv5-rGT15IRX-_Gg4nJ5wqqR_6YaDi8",
            "alg": "EdDSA"
        }
    ),
    publicKeyWrong: JWK.asKey(
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
        let signature = sign(rs256TestResource.jwtDecoded.payload, rs256TestResource.kid, rs256TestResource.privateKey, ALGORITHMS.RS256);
        let validPayload = verify(signature, rs256TestResource.publicKey, ALGORITHMS.RS256);
        expect(validPayload).toMatchObject(rs256TestResource.jwtDecoded.payload);
        expect(() => {
            validPayload = verify(signature, rs256TestResource.publicKeyWrong, ALGORITHMS.RS256);
        }).toThrow(new Error(ERRORS.INVALID_SIGNATURE));
    });
    test('JWT signing and verification ES256K', async () => {
        let signature = sign(es256kTestResource.jwtDecoded.payload, es256kTestResource.kid, es256kTestResource.privateKey, ALGORITHMS.ES256K);
        let validPayload = verify(signature, es256kTestResource.publicKey, ALGORITHMS.ES256K);
        expect(validPayload).toMatchObject(es256kTestResource.jwtDecoded.payload);
        expect(() => {
            validPayload = verify(signature, es256kTestResource.publicKeyWrong, ALGORITHMS.ES256K);
        }).toThrow(new Error(ERRORS.INVALID_SIGNATURE));
    }),
    test('JWT signing and verification ES256K-R', async () => {
        let signature = sign(es256kRecoverableResources.jwtDecoded.payload, es256kRecoverableResources.kid, es256kRecoverableResources.privateKey, ALGORITHMS["ES256K-R"]);
        let validPayload = verify(signature, es256kRecoverableResources.publicKey, ALGORITHMS["ES256K-R"]);
        expect(validPayload).toMatchObject(es256kRecoverableResources.jwtDecoded.payload);
        expect(() => {
            validPayload = verify(signature, es256kRecoverableResources.publicKeyWrong, ALGORITHMS["ES256K-R"]);
        }).toThrow(new Error(ERRORS.INVALID_SIGNATURE));
    })
    test('JWT signing and verification EdDSA', async () => {
        let signature = sign(edDsaTestResources.jwtDecoded.payload, edDsaTestResources.kid, edDsaTestResources.privateKey, ALGORITHMS.EdDSA);
        let validPayload = verify(signature, edDsaTestResources.publicKey, ALGORITHMS.EdDSA);
        expect(validPayload).toMatchObject(edDsaTestResources.jwtDecoded.payload);
        expect(() => {
            validPayload = verify(signature, edDsaTestResources.publicKeyWrong, ALGORITHMS.EdDSA);
        }).toThrow(new Error(ERRORS.INVALID_SIGNATURE));
    })
})