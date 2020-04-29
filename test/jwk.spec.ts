import { JWK } from 'jose';
import {KeyObjects, RSAKey, getECKey, getOKP, KeyInputs} from '../src/JWKUtils'

describe('JWK functions', function () {
    test('RS256Key functions', async ()=>{
        let kid: string = 'key_1';
        let publicJWK: KeyObjects.RSAPublicKeyObject = {
            "kty": "RSA",
            "e": "AQAB",
            "use": "enc",
            "kid": "key_1",
            "alg": "RS256",
            "n": "hgU7BWR8A_d5Z4boXZaff3KLte8rEZvA5mGRRF_WMEqp2l9K2dkgT-Z27sSAi-uZrkFKRxtclyW2ZCU4uv5jJH9yWcmksxfV-VYpCFiJVPKiAxTFftUNB0jiFsJDAxgfECorJkYn1s9BbNMzbuiNzUvBqTXKS2Q6rFj0lrCR_mZSwZl1zBW5Rh5c2vK8rWkQ7q2T_Q2eT2QOonzmhfTSZDneqyaOKjom9QRbWgnR6vbVb9beUzZ7W5Y_grdIoQ7VZS5SDdEJrGWrquzmsfigvcuWBbGQw5wnN1cJjWTElITN0FTCJpK2KOuQbQnBtOV9T7hUkGKFmhyDqeclBcDopw"
        }
        let privateJWK: KeyObjects.RSAPrivateKeyObject = {
            "p": "0riZ2TyPf66nQpV4iuTdHBsVjIqDBeBq17VOhcf2qma1yIhkVKs5xUFUmDHeXHFIJnP6tnlRkxWgQYKJcicFwuoROkZXByN8qxjC5gc_Yt72oV2j_tZti65khLQ9tG6PW31euxniw42ND2rV-hne77uC8QDFVVoDqADwh_nlyTE",
            "kty": "RSA",
            "q": "otF1yZwtMBLiAWi04UTU9vg_4IDXTpCqGatVyLYoPLAhB5BJ4s41Yfop7bI7AsYP6ZjFQBuC5rjZ6OmItgkFu6Ha5lOPl1C36vr7hC_fqWLkLwL8cNZ8pZ5_RO0XOFtc10Zv5pNZypJjLHgnDjM7oDyV0YqA7dBLoxrcFytP2Vc",
            "d": "Om0vVOOAuU37LGoBBUP0FuC-DbvNv-hyCT3B0dgiDX2PXPcsL5rb3llvwhoCnH1Cy1gFZMiF7hLv1-ruN39Ng4zYMlKZLcaXbxLj4pKOlG0Oul8k1m1VN7bLcfaQtlmeuTJZC1-MYLaMJEBS7OgPYc_EBtu_bGyus5I4VzV1AD3Cv0Kjp5lKb_V8GEshFbsCIszkdXyfGH7PF3SwmsHkyiEEKlCyInLtV1kEPV1s8-ekz9UdhL8_Q-BZRT0JzpsRErgrzQgGZEHp0rXeaMRQWlQWJic4kKdWuTYzSNuDTPyIo8YZhCxOWdQP__saHSi3nfqf8wBl6k3CeRkRAlpVYQ",
            "e": "AQAB",
            "use": "enc",
            "kid": "key_1",
            "qi": "O8ZQbD3Y4mh-rMIY0tQJFfPbxMeabWB0htpx1Ry9Y3LJR1U4EHxMmVFD9WLFQfie_Qg0RZNCKCj_cKn_pbL4LxthHV9sF8Wg2O7QBL7ajQHVnN1-SDyhKq3hbq58NJ8dT5gttuY3TOFuIb5vkSMjNvlIZC4cGk2YIMewkfspsm8",
            "dp": "Co14FurzfL9wXONDYCFJ-WhZ0en12ct9TkQkJIr5DVuLavl5nMveXsSAygZlTlfV9ycDvTOiJC2HEwDIhVDy9unl5vcy0Ia0bZUV3ZMrV3Y2_6nC1rZCUiZvnj2wgWKwBzLmFZScSJLEJ6t__8Bf672GNy-EsluJp1Y0tXqMSWE",
            "alg": "RS256",
            "dq": "Sr1kGHw8sgi4_nSWM6JpMEWc7O236DS4ILhp1Izpw5IGV3aAtEB8eNFhVd-u_wL0YwLh6R-34zmPrj8lpopVu1_9ICXTkF5ZTuCPfIqNXTAsFviD8ThEV7J-MaG0OwaVg6ytyWZynW69X7h4FSinglLNYzb1IDWxwtmdlnUnXlk",
            "n": "hgU7BWR8A_d5Z4boXZaff3KLte8rEZvA5mGRRF_WMEqp2l9K2dkgT-Z27sSAi-uZrkFKRxtclyW2ZCU4uv5jJH9yWcmksxfV-VYpCFiJVPKiAxTFftUNB0jiFsJDAxgfECorJkYn1s9BbNMzbuiNzUvBqTXKS2Q6rFj0lrCR_mZSwZl1zBW5Rh5c2vK8rWkQ7q2T_Q2eT2QOonzmhfTSZDneqyaOKjom9QRbWgnR6vbVb9beUzZ7W5Y_grdIoQ7VZS5SDdEJrGWrquzmsfigvcuWBbGQw5wnN1cJjWTElITN0FTCJpK2KOuQbQnBtOV9T7hUkGKFmhyDqeclBcDopw"
        }
        let privatePem = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAhgU7BWR8A/d5Z4boXZaff3KLte8rEZvA5mGRRF/WMEqp2l9K
2dkgT+Z27sSAi+uZrkFKRxtclyW2ZCU4uv5jJH9yWcmksxfV+VYpCFiJVPKiAxTF
ftUNB0jiFsJDAxgfECorJkYn1s9BbNMzbuiNzUvBqTXKS2Q6rFj0lrCR/mZSwZl1
zBW5Rh5c2vK8rWkQ7q2T/Q2eT2QOonzmhfTSZDneqyaOKjom9QRbWgnR6vbVb9be
UzZ7W5Y/grdIoQ7VZS5SDdEJrGWrquzmsfigvcuWBbGQw5wnN1cJjWTElITN0FTC
JpK2KOuQbQnBtOV9T7hUkGKFmhyDqeclBcDopwIDAQABAoIBADptL1TjgLlN+yxq
AQVD9Bbgvg27zb/ocgk9wdHYIg19j1z3LC+a295Zb8IaApx9QstYBWTIhe4S79fq
7jd/TYOM2DJSmS3Gl28S4+KSjpRtDrpfJNZtVTe2y3H2kLZZnrkyWQtfjGC2jCRA
UuzoD2HPxAbbv2xsrrOSOFc1dQA9wr9Co6eZSm/1fBhLIRW7AiLM5HV8nxh+zxd0
sJrB5MohBCpQsiJy7VdZBD1dbPPnpM/VHYS/P0PgWUU9Cc6bERK4K80IBmRB6dK1
3mjEUFpUFiYnOJCnVrk2M0jbg0z8iKPGGYQsTlnUD//7Gh0ot536n/MAZepNwnkZ
EQJaVWECgYEA0riZ2TyPf66nQpV4iuTdHBsVjIqDBeBq17VOhcf2qma1yIhkVKs5
xUFUmDHeXHFIJnP6tnlRkxWgQYKJcicFwuoROkZXByN8qxjC5gc/Yt72oV2j/tZt
i65khLQ9tG6PW31euxniw42ND2rV+hne77uC8QDFVVoDqADwh/nlyTECgYEAotF1
yZwtMBLiAWi04UTU9vg/4IDXTpCqGatVyLYoPLAhB5BJ4s41Yfop7bI7AsYP6ZjF
QBuC5rjZ6OmItgkFu6Ha5lOPl1C36vr7hC/fqWLkLwL8cNZ8pZ5/RO0XOFtc10Zv
5pNZypJjLHgnDjM7oDyV0YqA7dBLoxrcFytP2VcCgYAKjXgW6vN8v3Bc40NgIUn5
aFnR6fXZy31ORCQkivkNW4tq+Xmcy95exIDKBmVOV9X3JwO9M6IkLYcTAMiFUPL2
6eXm9zLQhrRtlRXdkytXdjb/qcLWtkJSJm+ePbCBYrAHMuYVlJxIksQnq3//wF/r
vYY3L4SyW4mnVjS1eoxJYQKBgEq9ZBh8PLIIuP50ljOiaTBFnOztt+g0uCC4adSM
6cOSBld2gLRAfHjRYVXfrv8C9GMC4ekft+M5j64/JaaKVbtf/SAl05BeWU7gj3yK
jV0wLBb4g/E4RFeyfjGhtDsGlYOsrclmcp1uvV+4eBUop4JSzWM29SA1scLZnZZ1
J15ZAoGAO8ZQbD3Y4mh+rMIY0tQJFfPbxMeabWB0htpx1Ry9Y3LJR1U4EHxMmVFD
9WLFQfie/Qg0RZNCKCj/cKn/pbL4LxthHV9sF8Wg2O7QBL7ajQHVnN1+SDyhKq3h
bq58NJ8dT5gttuY3TOFuIb5vkSMjNvlIZC4cGk2YIMewkfspsm8=
-----END RSA PRIVATE KEY-----
`
        let publicPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhgU7BWR8A/d5Z4boXZaf
f3KLte8rEZvA5mGRRF/WMEqp2l9K2dkgT+Z27sSAi+uZrkFKRxtclyW2ZCU4uv5j
JH9yWcmksxfV+VYpCFiJVPKiAxTFftUNB0jiFsJDAxgfECorJkYn1s9BbNMzbuiN
zUvBqTXKS2Q6rFj0lrCR/mZSwZl1zBW5Rh5c2vK8rWkQ7q2T/Q2eT2QOonzmhfTS
ZDneqyaOKjom9QRbWgnR6vbVb9beUzZ7W5Y/grdIoQ7VZS5SDdEJrGWrquzmsfig
vcuWBbGQw5wnN1cJjWTElITN0FTCJpK2KOuQbQnBtOV9T7hUkGKFmhyDqeclBcDo
pwIDAQAB
-----END PUBLIC KEY-----
`
        let key = RSAKey.fromPublicKey({
            key: publicPem,
            kid: kid,
            use: 'enc',
            format: KeyInputs.FORMATS.PEM,
        });
        expect(key.toJWK()).toMatchObject(publicJWK);
        let pem = key.toPEM();
        expect(pem.split('\n').join('')).toEqual(publicPem.split('\n').join(''));

        key = RSAKey.fromPrivateKey({
            key: privatePem,
            kid: kid,
            use: 'enc',
            format: KeyInputs.FORMATS.PEM,
        });
        expect(key.toJWK()).toMatchObject(privateJWK);
        pem = key.toPEM('pkcs1');
        expect(pem.split('\n').join('')).toEqual(privatePem.split('\n').join(''));
    });
    test('OKP retrieval', async () => {
        let kid = "key_1";
        let expectedPublic = JWK.asKey({
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "key_1",
            "x": "wTqgGR7jLFnH3Ypj-RilupLwu_JGO5k9kAPEVzGTSLw",
            "alg": "EdDSA"
        });
        let expectedPrivate = JWK.asKey({
            "kty": "OKP",
            "d": "LhsIL614LTGMp3zqD3dMnTTRhA4tUSYfovBJTnqH1io",
            "crv": "Ed25519",
            "kid": "key_1",
            "x": "wTqgGR7jLFnH3Ypj-RilupLwu_JGO5k9kAPEVzGTSLw",
            "alg": "EdDSA"
        });

        let base58StrPublic = 'E1HXzEPZQ4LjFLwCeMArbFx4uEeuy6sgkTmkspaCHZCo';
        let received = getOKP(base58StrPublic, kid, KeyInputs.FORMATS.BASE58);
        expect(received).toEqual(expectedPublic);

        let base64StrPublic = 'wTqgGR7jLFnH3Ypj+RilupLwu/JGO5k9kAPEVzGTSLw=';
        received = getOKP(base64StrPublic, expectedPublic.kid, KeyInputs.FORMATS.BASE64);
        expect(received).toEqual(expectedPublic);

        let hexStrPublic = 'c13aa0191ee32c59c7dd8a63f918a5ba92f0bbf2463b993d9003c457319348bc';
        received = getOKP(hexStrPublic, kid, KeyInputs.FORMATS.HEX);
        expect(received).toEqual(expectedPublic);

        let base58StrPrivate = '46yfMfV4FAH11pWEpggYxxtyUeunP9bfZZb5JYSr1u9T';
        received = getOKP(base58StrPrivate, kid, KeyInputs.FORMATS.BASE58, false);
        expect(received).toEqual(expectedPrivate);

        let base64StrPrivate = 'LhsIL614LTGMp3zqD3dMnTTRhA4tUSYfovBJTnqH1io=';
        received = getOKP(base64StrPrivate, kid, KeyInputs.FORMATS.BASE64, false);
        expect(received).toEqual(expectedPrivate);

        let hexStrPrivate = '2e1b082fad782d318ca77cea0f774c9d34d1840e2d51261fa2f0494e7a87d62a';
        received = getOKP(hexStrPrivate, kid, KeyInputs.FORMATS.HEX, false);
        expect(received).toEqual(expectedPrivate);
    });
    test('ECKey Retrieval', async () => {
        let kid = "key_1";
        let expectedPublic = JWK.asKey({
            "kty": "EC",
            "crv": "secp256k1",
            "kid": "key_1",
            "x": "dkp-YKIFz9Cg06D07uwLLHj3LbgHjv1HiiiXCJXrE1k",
            "y": "3QQZB8pJjP7FNoZ19EQjGSorXmxGtj4bs4clyoeB_fY",
            "alg": "ES256K"
        });
        let expectedPrivate = JWK.asKey({
            "kty": "EC",
            "d": "9aANYnB315hk6vlQGjKTQj-jKTNjYfmUVoeW0ogLaWg",
            "crv": "secp256k1",
            "kid": "key_1",
            "x": "dkp-YKIFz9Cg06D07uwLLHj3LbgHjv1HiiiXCJXrE1k",
            "y": "3QQZB8pJjP7FNoZ19EQjGSorXmxGtj4bs4clyoeB_fY",
            "alg": "ES256K"
        });

        let hexStrPublic = '02764a7e60a205cfd0a0d3a0f4eeec0b2c78f72db8078efd478a28970895eb1359';
        let received = getECKey(hexStrPublic, kid, KeyInputs.FORMATS.HEX);
        expect(received).toEqual(expectedPublic);

        let hexStrPrivate = 'f5a00d627077d79864eaf9501a3293423fa329336361f994568796d2880b6968';
        received = getECKey(hexStrPrivate, kid, KeyInputs.FORMATS.HEX, false);
        expect(received).toEqual(expectedPrivate);
    });
})
