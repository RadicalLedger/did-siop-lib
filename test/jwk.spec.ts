import { JWK } from 'jose';
import * as JWKUtils from '../src/JWKUtils'

describe('JWK functions', function () {
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
        let received = JWKUtils.getOKP(base58StrPublic, kid, JWKUtils.KEYFORMATS.publicKeyBase58);
        expect(received).toEqual(expectedPublic);

        let base64StrPublic = 'wTqgGR7jLFnH3Ypj+RilupLwu/JGO5k9kAPEVzGTSLw=';
        received = JWKUtils.getOKP(base64StrPublic, expectedPublic.kid, JWKUtils.KEYFORMATS.publicKeyBase64);
        expect(received).toEqual(expectedPublic);

        let hexStrPublic = 'c13aa0191ee32c59c7dd8a63f918a5ba92f0bbf2463b993d9003c457319348bc';
        received = JWKUtils.getOKP(hexStrPublic, kid, JWKUtils.KEYFORMATS.publicKeyHex);
        expect(received).toEqual(expectedPublic);

        let base58StrPrivate = '46yfMfV4FAH11pWEpggYxxtyUeunP9bfZZb5JYSr1u9T';
        received = JWKUtils.getOKP(base58StrPrivate, kid, JWKUtils.KEYFORMATS.publicKeyBase58, false);
        expect(received).toEqual(expectedPrivate);

        let base64StrPrivate = 'LhsIL614LTGMp3zqD3dMnTTRhA4tUSYfovBJTnqH1io=';
        received = JWKUtils.getOKP(base64StrPrivate, kid, JWKUtils.KEYFORMATS.publicKeyBase64, false);
        expect(received).toEqual(expectedPrivate);

        let hexStrPrivate = '2e1b082fad782d318ca77cea0f774c9d34d1840e2d51261fa2f0494e7a87d62a';
        received = JWKUtils.getOKP(hexStrPrivate, kid, JWKUtils.KEYFORMATS.publicKeyHex, false);
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
        let received = JWKUtils.getECKey(hexStrPublic, kid, JWKUtils.KEYFORMATS.publicKeyHex);
        expect(received).toEqual(expectedPublic);

        let hexStrPrivate = 'f5a00d627077d79864eaf9501a3293423fa329336361f994568796d2880b6968';
        received = JWKUtils.getECKey(hexStrPrivate, kid, JWKUtils.KEYFORMATS.publicKeyHex, false);
        expect(received).toEqual(expectedPrivate);
    });
})
