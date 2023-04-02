import {
    KeySet,
    calculateThumbprint,
    KeyObjects,
    RSAKey,
    ECKey,
    OKP,
    ERRORS
} from './../src/core/jwk-utils';
import { KEY_FORMATS, KTYS, ALGORITHMS } from './../src/core/globals';
import { TD_KEY_PAIRS } from './data/key-pairs.testdata';
import nock from 'nock';

describe('JWK functions', function () {
    test('RSAKey functions', async () => {
        let kid: string = 'key_1';
        let publicJWK: KeyObjects.RSAPublicKeyObject = TD_KEY_PAIRS.rsa_1.publicJWK;
        let publicMinimalJWK = TD_KEY_PAIRS.rsa_1.publicMinimalJWK;
        let publicJWKThumbprint = TD_KEY_PAIRS.rsa_1.publicJWKThumbprint;
        let privateJWK: KeyObjects.RSAPrivateKeyObject = TD_KEY_PAIRS.rsa_1.privateJWK;
        let privateMinimalJWK = TD_KEY_PAIRS.rsa_1.privateMinimalJWK;
        let privatePem = TD_KEY_PAIRS.rsa_1.privatePem;
        let publicPem = TD_KEY_PAIRS.rsa_1.publicPem;

        let key = RSAKey.fromKey({
            key: publicPem,
            kid: kid,
            use: 'enc',
            alg: ALGORITHMS[ALGORITHMS.RS256],
            kty: KTYS[KTYS.RSA],
            format: KEY_FORMATS.PKCS8_PEM,
            isPrivate: false
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
            isPrivate: true
        });
        expect(key.toJWK(true)).toMatchObject(privateJWK);
        pem = key.exportKey(KEY_FORMATS.PKCS1_PEM);
        expect(pem.split('\n').join('')).toEqual(privatePem.split('\n').join(''));
        minimalJWK = key.getMinimalJWK(true);
        expect(minimalJWK).toMatchObject(privateMinimalJWK);
    });
    test('ECKey functions', async () => {
        let kid: string = 'key_1';
        let publicJWK: KeyObjects.ECPublicKeyObject = TD_KEY_PAIRS.ec_1.publicJWK;
        let publicMinimalJWK = TD_KEY_PAIRS.ec_1.publicMinimalJWK;
        let publicJWKThumbprint = TD_KEY_PAIRS.ec_1.publicJWKThumbprint;
        let privateJWK: KeyObjects.ECPrivateKeyObject = TD_KEY_PAIRS.ec_1.privateJWK;
        let privateMinimalJWK = TD_KEY_PAIRS.ec_1.privateMinimalJWK;

        let key = ECKey.fromKey(privateJWK);
        let privateHex = key.exportKey(KEY_FORMATS.HEX);
        let retrievedJWK = ECKey.fromKey({
            key: privateHex,
            kid: kid,
            use: 'enc',
            alg: ALGORITHMS[ALGORITHMS.ES256K],
            kty: KTYS[KTYS.EC],
            format: KEY_FORMATS.HEX,
            isPrivate: true
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
            isPrivate: false
        }).toJWK();
        expect(retrievedJWK).toMatchObject(publicJWK);

        minimalJWK = key.getMinimalJWK(false);
        expect(minimalJWK).toMatchObject(publicMinimalJWK);
        let thumbprint = calculateThumbprint(minimalJWK);
        expect(thumbprint).toEqual(publicJWKThumbprint);
    });
    test('OKP functions', async () => {
        let kid: string = 'key_1';
        let publicJWK: KeyObjects.OKPPublicKeyObject = TD_KEY_PAIRS.okp_1.publicJWK;
        let publicMinimalJWK = TD_KEY_PAIRS.okp_1.publicMinimalJWK;
        let publicJWKThumbprint = TD_KEY_PAIRS.okp_1.publicJWKThumbprint;
        let privateJWK: KeyObjects.OKPPrivateKeyObject = TD_KEY_PAIRS.okp_1.privateJWK;
        let privateMinimalJWK = TD_KEY_PAIRS.okp_1.privateMinimalJWK;

        let key = OKP.fromKey(privateJWK);
        let privateBase58 = key.exportKey(KEY_FORMATS.BASE58);
        let retrievedJWK = OKP.fromKey({
            key: privateBase58,
            kid: kid,
            use: 'enc',
            alg: ALGORITHMS[ALGORITHMS.EdDSA],
            kty: KTYS[KTYS.OKP],
            format: KEY_FORMATS.BASE58,
            isPrivate: true
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
            isPrivate: false
        }).toJWK();
        expect(retrievedJWK).toMatchObject(publicJWK);

        minimalJWK = key.getMinimalJWK(false);
        expect(minimalJWK).toMatchObject(publicMinimalJWK);
        let thumbprint = calculateThumbprint(minimalJWK);
        expect(thumbprint).toEqual(publicJWKThumbprint);
    });
});
describe('JWKS', function () {
    test('KeySet functions', async () => {
        let jwks = new KeySet();
        expect(jwks.size()).toEqual(0);

        const rsa1 = TD_KEY_PAIRS.rsa_2.publicJWK;
        const rsa2 = TD_KEY_PAIRS.rsa_3.publicJWK;
        const ec1 = TD_KEY_PAIRS.ec_2.publicJWK;
        const ec2 = TD_KEY_PAIRS.ec_3.publicJWK;
        const okp1 = TD_KEY_PAIRS.okp_2.publicJWK;
        const okp2 = TD_KEY_PAIRS.okp_3.publicJWK;

        const set = {
            keys: [rsa1, ec1, ec2, okp1]
        };

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

        nock('http://localhost')
            .get('/keys')
            .reply(200, set)
            .get('/invalidUri')
            .reply(404, 'Not found');

        jwks = new KeySet();
        await jwks.setURI('http://localhost/keys');
        expect(jwks.size()).toEqual(set.keys.length);

        jwks = new KeySet();
        let jwksResolvePromise = jwks.setURI('http://localhost/invalidUri');
        await expect(jwksResolvePromise).rejects.toEqual(new Error(ERRORS.URI_ERROR));
    });
});
