import { JWK } from 'jose';
//import { eddsa as EdDSA } from 'elliptic';
import * as JWKUtils from '../src/JWKUtils'
//import * as base58 from 'bs58';
//import base64url from 'base64url';

describe('JWK functions',  function(){
    test('OKP retrieval', async ()=>{
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
})
