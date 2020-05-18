import { JWTObject } from './../src/core/JWT';
import { Provider } from './../src/core/Provider';
import { RP } from '../src/core/RP';
import { ALGORITHMS, KEY_FORMATS } from '../src/core/globals';

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

        let rp = await RP.getRP(
            'https://my.rp.com/cb',
            'did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83',
            {
                "jwks_uri": "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
                "id_token_signed_response_alg": ["ES256K", "ES256K-R", "EdDSA", "RS256"]
            }
        );

        let rpPrivateKey = 'CE438802C1F0B6F12BC6E686F372D7D495BC5AA634134B4A7EA4603CB25F0964';
        let rpKid = 'did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83#owner';

        rp.addSigningParams(rpPrivateKey, rpKid, KEY_FORMATS.HEX, ALGORITHMS["ES256K-R"]);

        let request =  await rp.generateRequest();

        let siop = new Provider();
        await siop.setUser('did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf');

        let userPrivateKeyHex = '3f81cb66c8cbba18fbe25f99d2fb4e19f54a1ee69c335ce756a705726189c9e7';
        let userKid = 'did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf#owner';

        siop.addSigningParams(userPrivateKeyHex, userKid, KEY_FORMATS.HEX, ALGORITHMS["ES256K-R"]);

        let requestJWTDecoded = await siop.validateRequest(request);

        expect(requestJWTDecoded).toMatchObject(requestObj);

        let response = await siop.generateResponse(requestJWTDecoded.payload);

        let responseJWTDecoded = await rp.validateResponse(response, {
            redirect_uri: 'https://my.rp.com/cb',
            isExpirable: true,
        })

        expect(responseJWTDecoded).toHaveProperty('header');
        expect(responseJWTDecoded).toHaveProperty('payload');

        rp.removeSigningParams('did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83#owner');
        let requestPromise = rp.generateRequest();

        expect(requestPromise).rejects.toEqual(new Error('Atleast one SigningInfo is required'));

        siop.removeSigningParams('did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf#owner');
        let responsePromise = siop.generateResponse(requestJWTDecoded.payload);

        expect(responsePromise).rejects.toEqual(new Error('Atleast one SigningInfo is required'));
    })
})