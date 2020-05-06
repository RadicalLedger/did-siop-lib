import { JWTObject } from './../src/JWT';
import { SIOP } from './../src/DID_SIOP';
import { ECKey } from '../src/JWKUtils';
import { SigningInfo } from '../src/JWT';
import { RP } from '../src/DID_SIOP_RP';
import { ALGORITHMS, KTYS, KEY_FORMATS } from '../src/globals';

describe('DID SIOP', function () {
    test('DID SIOP end to end functions testing', async () => {
        jest.setTimeout(10000);
        
        let requestObj: JWTObject = {
            header: {
                "alg": "ES256K-R",
                "typ": "JWT",
                "kid": "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83#owner"
            },
            payload:{
                "iss": "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83",
                "response_type": "id_token",
                "scope": "openid did_authn",
                "client_id": "https://my.rp.com/cb",
                "registration": {
                  "jwks_uri": "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
                  "id_token_signed_response_alg": [
                    "ES256K",
                    "ES256K-R",
                    "EdDSA",
                    "RS256"
                  ]
                }
              }
        }

        let rp = new RP(
            'https://my.rp.com/cb',
            'did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83',
            {
                "jwks_uri": "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
                "id_token_signed_response_alg": ["ES256K", "ES256K-R", "EdDSA", "RS256"]
            }
        );

        let rpSigningInfo: SigningInfo = {
            alg: ALGORITHMS["ES256K-R"],
            publicKey_kid: 'did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83#owner',
            privateKey: ECKey.fromKey({
                key: 'CE438802C1F0B6F12BC6E686F372D7D495BC5AA634134B4A7EA4603CB25F0964',
                kid: 'did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83#owner',
                use: 'sig',
                kty: KTYS[KTYS.EC],
                format: KEY_FORMATS.HEX,
                isPrivate: true,
            }),
        }

        rp.addSigningParams(rpSigningInfo);

        let request =  await rp.generateRequest();

        let siop = new SIOP();
        await siop.setUser('did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf');

        let siopSigningInfo: SigningInfo = {
            alg: ALGORITHMS["ES256K-R"],
            publicKey_kid: 'did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf#owner',
            privateKey: ECKey.fromKey({
                key: '3f81cb66c8cbba18fbe25f99d2fb4e19f54a1ee69c335ce756a705726189c9e7',
                kid: 'did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf#owner',
                use: 'sig',
                kty: KTYS[KTYS.EC],
                format: KEY_FORMATS.HEX,
                isPrivate: true,
            }),
        }
        siop.addSigningParams(siopSigningInfo);

        let requestJWTDecoded = await siop.validateRequest(request);

        expect(requestJWTDecoded).toMatchObject(requestObj);

        let response = await siop.generateResponse(requestJWTDecoded.payload);

        let responseJWTDecoded = await rp.validateResponse(response, {
            redirect_uri: 'https://my.rp.com/cb',
            isExpirable: true,
        })

        expect(responseJWTDecoded).toHaveProperty('header');
        expect(responseJWTDecoded).toHaveProperty('payload');
    })
})