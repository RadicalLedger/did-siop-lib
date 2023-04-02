import {
    RSAVerifier,
    ECVerifier,
    ES256KRecoverableVerifier,
    OKPVerifier
} from './../src/core/verifiers';
import { RSASigner, ECSigner, ES256KRecoverableSigner, OKPSigner } from './../src/core/signers';
import { RSAKey, ECKey, OKP } from '../src/core/jwk-utils';
import { ALGORITHMS } from '../src/core/globals';
import { checkKeyPair } from '../src/core/utils';
import { TD_KEY_PAIRS, TD_KEY_PAIRS_INVALID } from './data/key-pairs.testdata';

describe('Utils checkKeyPair with different keys', function () {
    let publicKey: any;
    let privateKey: any;

    test('checkKeyPair with valid RSA, EC, ES256KR, OKP Key types', async () => {
        publicKey = RSAKey.fromKey(TD_KEY_PAIRS.rsa_1.publicJWK);
        privateKey = RSAKey.fromKey(TD_KEY_PAIRS.rsa_1.privateJWK);

        let validity = checkKeyPair(
            privateKey,
            publicKey,
            new RSASigner(),
            new RSAVerifier(),
            ALGORITHMS.RS256
        );
        expect(validity).toBeTruthy();

        publicKey = ECKey.fromKey(TD_KEY_PAIRS.ec_1.publicJWK);
        privateKey = ECKey.fromKey(TD_KEY_PAIRS.ec_1.privateJWK);

        validity = checkKeyPair(
            privateKey,
            publicKey,
            new ECSigner(),
            new ECVerifier(),
            ALGORITHMS.ES256K
        );
        expect(validity).toBeTruthy();

        publicKey = TD_KEY_PAIRS.es256kr_1.publicKey;
        privateKey = TD_KEY_PAIRS.es256kr_1.privateKey;

        validity = checkKeyPair(
            privateKey,
            publicKey,
            new ES256KRecoverableSigner(),
            new ES256KRecoverableVerifier(),
            ALGORITHMS['ES256K-R']
        );
        expect(validity).toBeTruthy();

        publicKey = OKP.fromKey(TD_KEY_PAIRS.okp_1.publicJWK);
        privateKey = OKP.fromKey(TD_KEY_PAIRS.okp_1.privateJWK);

        validity = checkKeyPair(
            privateKey,
            publicKey,
            new OKPSigner(),
            new OKPVerifier(),
            ALGORITHMS.EdDSA
        );
        expect(validity).toBeTruthy();
    });

    test('checkKeyPair with invalid RSA, EC, ES256KR, OKP Key types', async () => {
        publicKey = RSAKey.fromKey(TD_KEY_PAIRS_INVALID.rsa_1.publicJWK);
        privateKey = RSAKey.fromKey(TD_KEY_PAIRS_INVALID.rsa_1.privateJWK);

        let validity = checkKeyPair(
            privateKey,
            publicKey,
            new RSASigner(),
            new RSAVerifier(),
            ALGORITHMS.RS256
        );
        expect(validity).toBeFalsy();

        publicKey = ECKey.fromKey(TD_KEY_PAIRS_INVALID.ec_1.publicJWK);
        privateKey = ECKey.fromKey(TD_KEY_PAIRS_INVALID.ec_1.privateJWK);

        validity = checkKeyPair(
            privateKey,
            publicKey,
            new ECSigner(),
            new ECVerifier(),
            ALGORITHMS.ES256K
        );
        expect(validity).toBeFalsy();

        publicKey = TD_KEY_PAIRS_INVALID.es256kr_1.publicKey;
        privateKey = TD_KEY_PAIRS_INVALID.es256kr_1.privateKey;

        validity = checkKeyPair(
            privateKey,
            publicKey,
            new ES256KRecoverableSigner(),
            new ES256KRecoverableVerifier(),
            ALGORITHMS['ES256K-R']
        );
        expect(validity).toBeFalsy();

        publicKey = OKP.fromKey(TD_KEY_PAIRS_INVALID.okp_1.publicJWK);
        privateKey = OKP.fromKey(TD_KEY_PAIRS_INVALID.okp_1.privateJWK);

        validity = checkKeyPair(
            privateKey,
            publicKey,
            new OKPSigner(),
            new OKPVerifier(),
            ALGORITHMS.EdDSA
        );
        expect(validity).toBeFalsy();
    });
});
