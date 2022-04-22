import { KeySet, calculateThumbprint } from './../src/core/JWKUtils';
import { KeyObjects, RSAKey, ECKey, OKP, ERRORS } from '../src/core/JWKUtils'
import { KEY_FORMATS, KTYS, ALGORITHMS } from './../src/core/globals';
import nock from 'nock';

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
        let publicMinimalJWK = {
            "e": "AQAB",
            "kty": "RSA",
            "n": "hgU7BWR8A_d5Z4boXZaff3KLte8rEZvA5mGRRF_WMEqp2l9K2dkgT-Z27sSAi-uZrkFKRxtclyW2ZCU4uv5jJH9yWcmksxfV-VYpCFiJVPKiAxTFftUNB0jiFsJDAxgfECorJkYn1s9BbNMzbuiNzUvBqTXKS2Q6rFj0lrCR_mZSwZl1zBW5Rh5c2vK8rWkQ7q2T_Q2eT2QOonzmhfTSZDneqyaOKjom9QRbWgnR6vbVb9beUzZ7W5Y_grdIoQ7VZS5SDdEJrGWrquzmsfigvcuWBbGQw5wnN1cJjWTElITN0FTCJpK2KOuQbQnBtOV9T7hUkGKFmhyDqeclBcDopw"
        }
        let publicJWKThumbprint = 'AJs7jRFXeJDuRgTTEjr92K5_LbCXkaKRGibrDH8Odv8';
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
        let privateMinimalJWK = {
            "d": "Om0vVOOAuU37LGoBBUP0FuC-DbvNv-hyCT3B0dgiDX2PXPcsL5rb3llvwhoCnH1Cy1gFZMiF7hLv1-ruN39Ng4zYMlKZLcaXbxLj4pKOlG0Oul8k1m1VN7bLcfaQtlmeuTJZC1-MYLaMJEBS7OgPYc_EBtu_bGyus5I4VzV1AD3Cv0Kjp5lKb_V8GEshFbsCIszkdXyfGH7PF3SwmsHkyiEEKlCyInLtV1kEPV1s8-ekz9UdhL8_Q-BZRT0JzpsRErgrzQgGZEHp0rXeaMRQWlQWJic4kKdWuTYzSNuDTPyIo8YZhCxOWdQP__saHSi3nfqf8wBl6k3CeRkRAlpVYQ",
            "dp": "Co14FurzfL9wXONDYCFJ-WhZ0en12ct9TkQkJIr5DVuLavl5nMveXsSAygZlTlfV9ycDvTOiJC2HEwDIhVDy9unl5vcy0Ia0bZUV3ZMrV3Y2_6nC1rZCUiZvnj2wgWKwBzLmFZScSJLEJ6t__8Bf672GNy-EsluJp1Y0tXqMSWE",
            "dq": "Sr1kGHw8sgi4_nSWM6JpMEWc7O236DS4ILhp1Izpw5IGV3aAtEB8eNFhVd-u_wL0YwLh6R-34zmPrj8lpopVu1_9ICXTkF5ZTuCPfIqNXTAsFviD8ThEV7J-MaG0OwaVg6ytyWZynW69X7h4FSinglLNYzb1IDWxwtmdlnUnXlk",
            "e": "AQAB",
            "kty": "RSA",
            "n": "hgU7BWR8A_d5Z4boXZaff3KLte8rEZvA5mGRRF_WMEqp2l9K2dkgT-Z27sSAi-uZrkFKRxtclyW2ZCU4uv5jJH9yWcmksxfV-VYpCFiJVPKiAxTFftUNB0jiFsJDAxgfECorJkYn1s9BbNMzbuiNzUvBqTXKS2Q6rFj0lrCR_mZSwZl1zBW5Rh5c2vK8rWkQ7q2T_Q2eT2QOonzmhfTSZDneqyaOKjom9QRbWgnR6vbVb9beUzZ7W5Y_grdIoQ7VZS5SDdEJrGWrquzmsfigvcuWBbGQw5wnN1cJjWTElITN0FTCJpK2KOuQbQnBtOV9T7hUkGKFmhyDqeclBcDopw",
            "p": "0riZ2TyPf66nQpV4iuTdHBsVjIqDBeBq17VOhcf2qma1yIhkVKs5xUFUmDHeXHFIJnP6tnlRkxWgQYKJcicFwuoROkZXByN8qxjC5gc_Yt72oV2j_tZti65khLQ9tG6PW31euxniw42ND2rV-hne77uC8QDFVVoDqADwh_nlyTE",
            "q": "otF1yZwtMBLiAWi04UTU9vg_4IDXTpCqGatVyLYoPLAhB5BJ4s41Yfop7bI7AsYP6ZjFQBuC5rjZ6OmItgkFu6Ha5lOPl1C36vr7hC_fqWLkLwL8cNZ8pZ5_RO0XOFtc10Zv5pNZypJjLHgnDjM7oDyV0YqA7dBLoxrcFytP2Vc",
            "qi": "O8ZQbD3Y4mh-rMIY0tQJFfPbxMeabWB0htpx1Ry9Y3LJR1U4EHxMmVFD9WLFQfie_Qg0RZNCKCj_cKn_pbL4LxthHV9sF8Wg2O7QBL7ajQHVnN1-SDyhKq3hbq58NJ8dT5gttuY3TOFuIb5vkSMjNvlIZC4cGk2YIMewkfspsm8",
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
        let key = RSAKey.fromKey({
            key: publicPem,
            kid: kid,
            use: 'enc',
            alg: ALGORITHMS[ALGORITHMS.RS256],
            kty: KTYS[KTYS.RSA],
            format: KEY_FORMATS.PKCS8_PEM,
            isPrivate: false,
        });
        expect(key.toJWK()).toMatchObject(publicJWK);
        let pem = key.exportKey(KEY_FORMATS.PKCS8_PEM);
        expect(pem.split('\n').join('')).toEqual(publicPem.split('\n').join(''));
        let minimalJWK = key.getMinimalJWK(false);
        expect(minimalJWK).toMatchObject(publicMinimalJWK);
        let thumbprint = calculateThumbprint(minimalJWK);
        expect(thumbprint).toEqual(publicJWKThumbprint);

        key = RSAKey.fromKey({
            key: privatePem,
            kid: kid,
            use: 'enc',
            alg: ALGORITHMS[ALGORITHMS.RS256],
            kty: KTYS[KTYS.RSA],
            format: KEY_FORMATS.PKCS1_PEM,
            isPrivate: true,
        });
        expect(key.toJWK(true)).toMatchObject(privateJWK);
        pem = key.exportKey(KEY_FORMATS.PKCS1_PEM);
        expect(pem.split('\n').join('')).toEqual(privatePem.split('\n').join(''));
        minimalJWK = key.getMinimalJWK(true);
        expect(minimalJWK).toMatchObject(privateMinimalJWK);
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
        let publicMinimalJWK = {
            "crv": "secp256k1",
            "kty": "EC",
            "x": "oquPKizfRHuR3YyX6X1Dw22aIoKi1UiVyVx9xA1f-XQ",
            "y": "luHPOmJDwPmr_BzTPN2fifkr6GZ-dmjm5TMrjBUvszQ",
        }
        let publicJWKThumbprint = 'qopwkempb7qhgC9XEyZAAs_-5kSZJEIh3yQAANgiJs4';
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
        let privateMinimalJWK = {
            "crv": "secp256k1",
            "d": "bnTMs3lArTEVvYUIyHXWbXOk_0GlDG__CkKaB4e-lm0",
            "kty": "EC",
            "x": "oquPKizfRHuR3YyX6X1Dw22aIoKi1UiVyVx9xA1f-XQ",
            "y": "luHPOmJDwPmr_BzTPN2fifkr6GZ-dmjm5TMrjBUvszQ",
        }

        let key = ECKey.fromKey(privateJWK);
        let privateHex = key.exportKey(KEY_FORMATS.HEX);
        let retrievedJWK = ECKey.fromKey({
            key: privateHex,
            kid: kid,
            use: 'enc',
            alg: ALGORITHMS[ALGORITHMS.ES256K],
            kty: KTYS[KTYS.EC],
            format: KEY_FORMATS.HEX,
            isPrivate: true,
        }).toJWK(true);
        expect(retrievedJWK).toMatchObject(privateJWK);

        let minimalJWK = key.getMinimalJWK(true);
        expect(minimalJWK).toMatchObject(privateMinimalJWK);

        key = ECKey.fromKey(publicJWK);
        let publicHex = key.exportKey(KEY_FORMATS.HEX);
        retrievedJWK = ECKey.fromKey({
            key: publicHex,
            kid: kid,
            use: 'enc',
            alg: ALGORITHMS[ALGORITHMS.ES256K],
            kty: KTYS[KTYS.EC],
            format: KEY_FORMATS.HEX,
            isPrivate: false,
        }).toJWK();
        expect(retrievedJWK).toMatchObject(publicJWK);

        minimalJWK = key.getMinimalJWK(false);
        expect(minimalJWK).toMatchObject(publicMinimalJWK);
        let thumbprint = calculateThumbprint(minimalJWK);
        expect(thumbprint).toEqual(publicJWKThumbprint);
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
        let publicMinimalJWK = {
            "crv": "Ed25519",
            "kty": "OKP",
            "x": "5_uoVZOQ--9RfCfwZXV6al-jNyyr9fKJRmt56DEQ8LI",
        }
        let publicJWKThumbprint = 'Dq8McRQuiLlWyvbS0_fvR5prE0X8zARyBaOyANbQxEw';
        let privateJWK: KeyObjects.OKPPrivateKeyObject = {
            "kty": "OKP",
            "d": "5EX3-YZgi5H2T2eLs9ytK0GbFE2Qm4teiAultZxC29U",
            "use": "enc",
            "crv": "Ed25519",
            "kid": "key_1",
            "x": "5_uoVZOQ--9RfCfwZXV6al-jNyyr9fKJRmt56DEQ8LI",
            "alg": "EdDSA"
        }
        let privateMinimalJWK = {
            "crv": "Ed25519",
            "d": "5EX3-YZgi5H2T2eLs9ytK0GbFE2Qm4teiAultZxC29U",
            "kty": "OKP",
            "x": "5_uoVZOQ--9RfCfwZXV6al-jNyyr9fKJRmt56DEQ8LI",
        }

        let key = OKP.fromKey(privateJWK);
        let privateBase58 = key.exportKey(KEY_FORMATS.BASE58);
        let retrievedJWK = OKP.fromKey({
            key: privateBase58,
            kid: kid,
            use: 'enc',
            alg: ALGORITHMS[ALGORITHMS.EdDSA],
            kty: KTYS[KTYS.OKP],
            format: KEY_FORMATS.BASE58,
            isPrivate: true,
        }).toJWK(true);
        expect(retrievedJWK).toMatchObject(privateJWK);

        let minimalJWK = key.getMinimalJWK(true);
        expect(minimalJWK).toMatchObject(privateMinimalJWK);

        key = OKP.fromKey(publicJWK);
        let publicBase58 = key.exportKey(KEY_FORMATS.BASE58);
        retrievedJWK = OKP.fromKey({
            key: publicBase58,
            kid: kid,
            use: 'enc',
            alg: ALGORITHMS[ALGORITHMS.EdDSA],
            kty: KTYS[KTYS.OKP],
            format: KEY_FORMATS.BASE58,
            isPrivate: false,
        }).toJWK();
        expect(retrievedJWK).toMatchObject(publicJWK);

        minimalJWK = key.getMinimalJWK(false);
        expect(minimalJWK).toMatchObject(publicMinimalJWK);
        let thumbprint = calculateThumbprint(minimalJWK);
        expect(thumbprint).toEqual(publicJWKThumbprint);
    });
})
describe('JWKS', function () {
    test('KeySet functions', async () => {
        let jwks = new KeySet();
        expect(jwks.size()).toEqual(0);

        const rsa1 = {
            "p": "0I0kWE9X7K63raZr_-3m_k_--xsKRFxHDGA1xskpEUY8ywgBeMIuk6KT1-dag8Q3PmIJKZd3G-nc9-H1GOw3RrBO25saPT0cnt5ujPI_o2atpCrLYDr7gy8N9cTQuod7I0gexm-U7-qaKk55jIisLV5_FqOwpNnSbryUGDKkumM",
            "kty": "RSA",
            "q": "oQfAVr3oLDemgtVAp63mbtxBhOm4JF7SY1H0sDSho5QMKrITRvmArwzmV9T8eiodGV9p7EcZhlRERBgRWDvRIrVfQdL3hzQ55JMCSbfB6eq3vLFco1IER4LVt2-1LzxuuGQBcJdsVnNt7bQdVrtr4tExaF04zzjXe8bGviY7jdc",
            "d": "G3Fn5XSoC4HZG86-BpEOYrO0gx5Nfd_BDzkyTF1wGAdlZ0khr-9AcybIWgZYc7vXYeeRKk92qxaKmMi2lpPwNrG267RL0upml_aZeke9W1scRWiAoGQQEbNgD08G0qe4hGrhHAJwNJoTJxLWvq5ZAZrLShKx1SAuBt1EcBp3cZ61Xj9Z-DTlrhiXJyGob9ZL8BC6aVT-b_brcT05Kh1vY5I5tOR6KUC17qGdqiUIXuUmnAyHWUsXN9kmzb6zKgkFagqrlQhLaXsMuP0ic75q3YaPX1Hl5HJVKr0rRTmE3w-UNgYsCdIwku_4zkdo5uJKXJ6l6GqN3PhYVpuCs5fA6Q",
            "e": "AQAB",
            "use": "sig",
            "kid": "rsa1",
            "qi": "XOH-lC58o4yN91Tiq-toECwe7_ujEO3YhFTHy5HWKfFGvMKl692UTlIt9iT6bgw90-kwpe3Uwkm7HioFKE6kpZ4KVNTOCFOlZQ5pNX39iJfVoisZ-Tvm1Af1sZUAT2JegwVi6i0MoJ2r6yVkQEERpw2VJaJqV8SqdhRL6UecCtc",
            "dp": "dHIqlgiPbn9L3fDrorZCYUNneuvpOqxPm3Bo9nrBrHyMW004DSZXfWWsqUPrvWEk-3cf6JJDFlnpYJtRED5sytKM5X_gEct6nJZUIeztbZ5aXCzs6-ljICd44v6nEU-uiM-vJ1uMTL2woOi6Y6a4hIib65cwfYuGPQCcrDoy0kM",
            "alg": "RS256",
            "dq": "hVvJA01FMRFpeeKoJ_XR56_LJwr0MFLDA_QEo8UCtFjQdq-BXX8V_mK9hLHj4jxsWu305_O-BMxWuNoBy0PGoGr6l6XizvsGkvDYrTpcgp-bSM7N_IfY-Ww2GDOQJq1yuIxB0P_mffYcbQaEYabX40ECHP9PI_ZcJqrpPuKk4YM",
            "n": "gy8UaA2yQDGuK7Dc4f6sYUkRyqYyWChQDHDPcXyN3Rw446C2ti-77XZpZxXRgceEkey2bZT8zHL6uMUrfmKkl1ujL9MHHkDvDVq86E8D54Kpx7K73K87OYnMcHdR2rPWjLRnpiO0sc4HHfNWLuz8TUzo-W1Om53qi853rdIOpBCpWwWgSs-mO17F26D-uZ4RnBNIv8WnYFbId87ddCY60_dsGBT0kj94v600jHn-akTCu_GZW5qwafrRhdXpFby9jinoGIJ7naNC39R27YrE2VIzJb_rK8HKtwML62EEoI5i90VpZ9hHBfHn86fKLPZdK9ycQ7sTfWZPBrtS6dIQJQ"
        }
        const rsa2 = {
            "kty": "RSA",
            "e": "AQAB",
            "use": "sig",
            "kid": "rsa2",
            "alg": "RS256",
            "n": "zuhMv8UeE5mMGajivOGpqA-SDfFsdkoGmZ0cIzxfvknBUJMyImQswuwiAhM3vrpd78yuxeBIr7riI_l7xNiSQTv9cBHbiAp67Z1Lq8ddd-AVnUCB3xMtZwaym4Fd4mQqEYYeRHm9HbuMsvuwbV__XefBaKELuapEXUcx3LLwvnh8nGGYhq8fOXhVoHpg1lGpwArCnLWQbZZkjrnkBj1CaYdYqOt_8fzkrTXoykSm-t-9Dsho3pR0trgjXakOy2NVlvI0IStP8M1RDVUgXjSgpOIwPaPPxjslOtr_a-deGscW4CinQoutL0i0FDpPsXGQ6f4B0Xjc1jfH0sM2ULO7DQ"
        }
        const ec1 = {
            "kty": "EC",
            "d": "9FDfRTfjBt-Z9_w9GXbjSNuI9pXTa_JzEKLG9B_FzwA",
            "use": "sig",
            "crv": "secp256k1",
            "kid": "ec1",
            "x": "ObMF-bBQvda4b-5stwN2Fqd83Be1BVSIn8IZ4q-x93w",
            "y": "m4Is5b3VJW0slR6wUNNcYyIffYmQKXnJ373-v5xladY",
            "alg": "ES256K"
        }
        const ec2 = {
            "kty": "EC",
            "use": "sig",
            "crv": "secp256k1",
            "kid": "ec2",
            "x": "hOr3CGcAc9JcFuZOCVXHpTGC-uXyEmhfXxX9IH5hZ_w",
            "y": "TK1ubE2SMOHzflF1Bk_R5QBlZ5fJLIMdsUtuT6j0g38",
            "alg": "ES256K"
        }
        const okp1 = {
            "kty": "OKP",
            "d": "MbzHqgiv4ogef4nLjdZzGQntFYcmQwlMpAXGoaa718Y",
            "use": "sig",
            "crv": "Ed25519",
            "kid": "okp1",
            "x": "FTynsSc6J-07cIBQskBnFm48PjWlgloc8bmwyE6mPjY",
            "alg": "EdDSA"
        }
        const okp2 = {
            "kty": "OKP",
            "use": "sig",
            "crv": "Ed25519",
            "kid": "okp2",
            "x": "Lcg5PqvtDePXKa_-ap-fJjInciQfuikgen_yyURYQhY",
            "alg": "EdDSA"
        }

        const set = {
            keys: [
                rsa1,
                ec1,
                ec2,
                okp1,
            ]
        }

        jwks.setKeys(set.keys);
        expect(jwks.size()).toEqual(set.keys.length);

        jwks.addKey(rsa2);
        expect(jwks.size()).toEqual(5);

        jwks.addKey(okp2);
        expect(jwks.size()).toEqual(6);

        jwks.removeKey('rsa1');
        expect(jwks.size()).toEqual(5);

        let retrieved = jwks.getKey('ec1');
        expect(retrieved[0].toJWK(true)).toEqual(ec1);

        nock('http://localhost').get('/keys').reply(200, set).get('/invalidUri').reply(404, 'Not found');

        jwks = new KeySet();
        await jwks.setURI('http://localhost/keys');
        expect(jwks.size()).toEqual(set.keys.length);

        jwks = new KeySet();
        let jwksResolvePromise = jwks.setURI('http://localhost/invalidUri');
        await expect(jwksResolvePromise).rejects.toEqual(new Error(ERRORS.URI_ERROR));
    })
})
