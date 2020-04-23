import { sign, ALGORITHMS } from '../src/JWT'
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
            "iat": 1516239022
        }
    },
    kid: 'key_1',
    privateKey: JWK.asKey(
        {
            "p": "-vGkgWkgwtMj-tkcG0YYoPHyfhutEQbBs6UbQR-wWxvhe-7z4zgXLPazAyo4cRYL9CDazF2QWUa_H1CFAgAAo5bHMVRZLSNFZUkG-rbsZFBMIvl4ijLxymeMO35xG-mqaOIR3AK8qlmTl0E6F9DVIzQBC1T3WDpjyKUYLRAwuVU",
            "kty": "RSA",
            "q": "tCMrOXiovBZbNA8tMAbZIdPKZSCBUeXh-EpeFe2EeVCFhA8Y2Ni5vjKlbMC5GWpJjmTC3yME3ZEbf-hs5cRH6LqCxeK0-fR8KFTAcC88i4BoP70pxW1sCL_QSBO8oRsWOahKfNmlUZrQqO4ILvVc1oj0zxagbwyuTqShNeEHpmE",
            "d": "QDFg7R5CwqDOxxUk6VSkceaLI3OSaPPy_l0BFahB6m8dKf-fG6SFFoUHok_hBhH6EBMZ-j5NZ930OVkDMQMlI3gxC2xuumhijpc3mIcvcjqthBWf6TQQOWjzpirkRco20lTGo1lHkBI3KHiNl-EVn6gWSTU4VeTopCivHUkGJbUhjRt9wWHfGoVl5_2zd-ojP5Zl6kxrmL9e5X2m2PXxSbNhct3Twd0RzxlEZupAnw0OP7O7-IVsozl6OaxXwBuVmwSjasUrWsYXlDJxQ01Ec31rK0w4KBaxfOZ6mKBOGidH2mBKCbeFcSA-pPVWff68Pc7HR_T7gE78ALJMnwXvgQ",
            "e": "AQAB",
            "use": "sig",
            "kid": "key_1",
            "qi": "TRYe-BiFz8FK22zHHDQGkCVfPsb2HlUTD-4pFAXt6jucW4p8N-dMNPjsZk-Mc1WOSyS8PV5oZkU5vzwr2JBXM7mW0-OXanjTJTVacL-Ind4X3ybYIDIiEXBsi5spJQQu6CK1tzSfwwcOTliQM2AIY9Q--H6Ockb7kcm5E0DxY5Q",
            "dp": "UESpDSf2bbsh4CRARE0YpaqemU36_t49aVwfqqYbQBlb98uIQZ74cs56lkGUCkA2FKHJuuMWwCfMDJUx5mDf03PwRUwotjJ5CRvh2qJWXQP-RpWrw_DlvIuApKsePQJyGthtRAWwGYFLn28iyOlos7j3uIs2DwemUVDVudxa6X0",
            "alg": "RS256",
            "dq": "hb-nFGD2R9EBnsG193beOTObj0J3QmvBQC1XdkiIl9qlh8v90uP35bSNBxaBWNGGE-fUmQDTV_-pv2q_kEoQakgxWORfI0fX98oVqDYqahnJTaoSHbiFAmoJJ7sfzy7hbaX6yICBMvoT-5nhEZy0dcXynuBZ9pofwdySpgKTP4E",
            "n": "sJRhE2hScf_-XZaXYYGX3XnkUh78tPiunCADo5B2T1-uF4o_G7qYVR-PTJiSdDqVUDPbIzbke9yV3S2NzV-Dmc7FmMGa9oCr0sLUpCC1IhhjcUwFXCNjT35XLPPEItcvrnZmJLm_hd6pIkjEFGa9Dkbqnt7YwquKB_yuxzFNgv3Gh4wT8jDTNgG34NX2SujKXb5oeFMcnFzsMGw5WSOecojAbXI_3xjXm32WjEw2lgOVE3MuPVhFLFqh1ckJLYYPbIe40rmBO2xvWcjlA29eIbh8jVhY5FZ9_sFvvKGT07zijjr_wKUnKtVOq8see-VYOZIN8JY27qT3ynlkgPZXNQ"
        }
    ),
    privateKeyWrong: {},
    publicKey: {},
    publicKeyWrong: {},
}

/* const es256kTestResource = {
    jwtDecoded: {
        header: {
            "alg": "ES256K",
            "typ": "JWT"
        },
        payload: {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022
        }
    },
    privateKey: '04418834408F4485404C428460C1D008040410827D0A97D1DF3CE0ED3BC5F0C7091045E9D41D135649DBBD315727C18EACFB15BA801C1814AE0410002A85100D080011362C69A8D266C546CE0B60E95E1872D834B913B56BF8610AAE2C4A19C1C72AD41D4BA3D3FF90E4377A10DD9DA3C38CD628626740199389D41B74217513FD8ABC',
    privateKeyWrong: '04418834408F4485404C428460C1D008040410827D0A97D1DF3CE0ED3BC5F0C7091045E9D41D135649DBBD315727C18EACFB15BA801C1814AE0410002A85100D080011362C69A8D266C546CE0B60E95E1872D834B913B56BF8610ABE2C4A19C1C72AD41D4BA3D3FF90E4377A10DD9DA3C38CD628626740199389D41B74217513FD8ABC',
    publicKey: '0428c0da3e1c15e84876625d366eab8dd20c84288bcf6a71a0699209fc656dcfeb4633d7eff3dc63be7d7ada54fcb63cd603e5ac0a1382de19a73487dbc8e177e9',
    publicKeyWrong: '0428c0da3e1c15e84876625d366eab8dd20c84288bcf6a71a0699209fc646dcfeb4633d7eff3dc63be7d7ada54fcb63cd603e5ac0a1382de19a73487dbc8e177e9',

} */

/* const es256kRecoverableResources = {
    jwtDecoded: {
        header: {
            "alg": "ES256K-R",
            "typ": "JWT"
        },
        payload: {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022
        }
    },
    privateKey: 'CE438802C1F0B6F12BC6E686F372D7D495BC5AA634134B4A7EA4603CB25F0964',
    privateKeyWrong: 'CE438802C1F0B6F12BC6E686F372D7D495BC5AA634134B4A7EA4603CB25F0944',
    publicKey: '0xB07Ead9717b44B6cF439c474362b9B0877CBBF83',
    publicKeyWrong: '0428c0da3e1c15e84876625d366eab8dd20c84288bcf6a71a0699209fc646dcfeb4633d7eff3dc63be7d7ada54fcb63cd603e5ac0a1382de19a73487dbc8e177e9',

} */

/* const edDsaTestResources = {
    jwtDecoded: {
        header: {
            "alg": "EdDSA",
            "typ": "JWT"
        },
        payload: {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022
        }
    },
    privateKey: '1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93',
    privateKeyWrong: '1498b5467a63dffa2dc9d9e069cff075d16fc33fdd4c3b01bfadae6433767d93',
    publicKey: 'b7a3c12dc0c8c748ab07525b701122b88bd78f600c76342d27f25e5f92444cde',
    publicKeyWrong: 'b7a3c12dc0c8c748ab07525b701122b88bd78f600c76342d27f24e5f92444cde',

} */

describe('JWT functions', function() {
    test('JWT signing', async () => {
        let signature = sign(rs256TestResource.jwtDecoded.payload, rs256TestResource.kid, rs256TestResource.privateKey, ALGORITHMS.RS256);
        console.log(signature);
    })
})