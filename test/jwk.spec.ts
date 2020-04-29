import { KeyObjects, RSAKey, ECKey, OKP, KeyInputs} from '../src/JWKUtils'

describe('JWK functions', function () {
    test('RSAKey functions', async ()=>{
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
    test('ECKey functions', async () => {
        let kid: string = 'key_1';
        let publicJWK: KeyObjects.ECPublicKeyObject = {
            "kty": "EC",
            "use": "enc",
            "crv": "secp256k1",
            "kid": "key_1",
            "x": "oquPKizfRHuR3YyX6X1Dw22aIoKi1UiVyVx9xA1f-XQ",
            "y": "luHPOmJDwPmr_BzTPN2fifkr6GZ-dmjm5TMrjBUvszQ",
            "alg": "ES256K"
        }
        let privateJWK: KeyObjects.ECPrivateKeyObject = {
            "kty": "EC",
            "d": "bnTMs3lArTEVvYUIyHXWbXOk_0GlDG__CkKaB4e-lm0",
            "use": "enc",
            "crv": "secp256k1",
            "kid": "key_1",
            "x": "oquPKizfRHuR3YyX6X1Dw22aIoKi1UiVyVx9xA1f-XQ",
            "y": "luHPOmJDwPmr_BzTPN2fifkr6GZ-dmjm5TMrjBUvszQ",
            "alg": "ES256K"
        }

        let key = ECKey.fromPrivateKey(privateJWK);
        let privateHex = key.toHex();
        let retrievedJWK = ECKey.fromPrivateKey({
            key: privateHex,
            kid: kid,
            use: 'enc',
            format: KeyInputs.FORMATS.HEX,
        }).toJWK();
        expect(retrievedJWK).toMatchObject(privateJWK);

        key = ECKey.fromPublicKey(publicJWK);
        let publicHex = key.toHex();
        retrievedJWK = ECKey.fromPublicKey({
            key: publicHex,
            kid: kid,
            use: 'enc',
            format: KeyInputs.FORMATS.HEX,
        }).toJWK();
        expect(retrievedJWK).toMatchObject(publicJWK);
    });
    test('OKP functions', async () => {
        let kid: string = 'key_1';
        let publicJWK: KeyObjects.OKPPublicKeyObject = {
            "kty": "OKP",
            "use": "enc",
            "crv": "Ed25519",
            "kid": "key_1",
            "x": "5_uoVZOQ--9RfCfwZXV6al-jNyyr9fKJRmt56DEQ8LI",
            "alg": "EdDSA"
        }
        let privateJWK: KeyObjects.OKPPrivateKeyObject = {
            "kty": "OKP",
            "d": "5EX3-YZgi5H2T2eLs9ytK0GbFE2Qm4teiAultZxC29U",
            "use": "enc",
            "crv": "Ed25519",
            "kid": "key_1",
            "x": "5_uoVZOQ--9RfCfwZXV6al-jNyyr9fKJRmt56DEQ8LI",
            "alg": "EdDSA"
        }

        let key = OKP.fromPrivateKey(privateJWK);
        let privateBase58 = key.toBase58();
        let retrievedJWK = OKP.fromPrivateKey({
            key: privateBase58,
            kid: kid,
            use: 'enc',
            format: KeyInputs.FORMATS.BASE58,
        }).toJWK();
        expect(retrievedJWK).toMatchObject(privateJWK);

        key = OKP.fromPublicKey(publicJWK);
        let publicBase58 = key.toBase58();
        retrievedJWK = OKP.fromPublicKey({
            key: publicBase58,
            kid: kid,
            use: 'enc',
            format: KeyInputs.FORMATS.BASE58,
        }).toJWK();
        expect(retrievedJWK).toMatchObject(publicJWK);
    });
})
describe('Signing and verifying', function () {
    test('RSA sign/verify', async ()=>{
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

        let privateKey = RSAKey.fromPrivateKey(privateJWK);
        let publicKey = RSAKey.fromPublicKey(publicJWK);

        let message = 'RSA test message';

        let signature = privateKey.sign(message);
        let validity = publicKey.verify(message, signature);
        expect(validity).toBeTruthy();
    });
    test('EC sign/verify', async () => {
        let publicJWK: KeyObjects.ECPublicKeyObject = {
            "kty": "EC",
            "use": "enc",
            "crv": "secp256k1",
            "kid": "key_1",
            "x": "oquPKizfRHuR3YyX6X1Dw22aIoKi1UiVyVx9xA1f-XQ",
            "y": "luHPOmJDwPmr_BzTPN2fifkr6GZ-dmjm5TMrjBUvszQ",
            "alg": "ES256K"
        }
        let privateJWK: KeyObjects.ECPrivateKeyObject = {
            "kty": "EC",
            "d": "bnTMs3lArTEVvYUIyHXWbXOk_0GlDG__CkKaB4e-lm0",
            "use": "enc",
            "crv": "secp256k1",
            "kid": "key_1",
            "x": "oquPKizfRHuR3YyX6X1Dw22aIoKi1UiVyVx9xA1f-XQ",
            "y": "luHPOmJDwPmr_BzTPN2fifkr6GZ-dmjm5TMrjBUvszQ",
            "alg": "ES256K"
        }

        let privateKey = ECKey.fromPrivateKey(privateJWK);
        let publicKey = ECKey.fromPublicKey(publicJWK);

        let message = 'EC test message';

        let signature = privateKey.sign(message);
        let validity = publicKey.verify(message, signature);
        expect(validity).toBeTruthy();
    });
    test('EC sign/verify', async () => {
        let publicJWK: KeyObjects.OKPPublicKeyObject = {
            "kty": "OKP",
            "use": "enc",
            "crv": "Ed25519",
            "kid": "key_1",
            "x": "5_uoVZOQ--9RfCfwZXV6al-jNyyr9fKJRmt56DEQ8LI",
            "alg": "EdDSA"
        }
        let privateJWK: KeyObjects.OKPPrivateKeyObject = {
            "kty": "OKP",
            "d": "5EX3-YZgi5H2T2eLs9ytK0GbFE2Qm4teiAultZxC29U",
            "use": "enc",
            "crv": "Ed25519",
            "kid": "key_1",
            "x": "5_uoVZOQ--9RfCfwZXV6al-jNyyr9fKJRmt56DEQ8LI",
            "alg": "EdDSA"
        }

        let privateKey = OKP.fromPrivateKey(privateJWK);
        let publicKey = OKP.fromPublicKey(publicJWK);

        let message = 'EdDSA test message';

        let signature = privateKey.sign(message);
        let validity = publicKey.verify(message, signature);
        expect(validity).toBeTruthy();
    })
})
