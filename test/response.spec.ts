import { DidSiopResponse } from './../src/core/Response';
import { Identity } from './../src/core/Identity';
import { SigningInfo } from './../src/core/JWT';
import { ALGORITHMS, KEY_FORMATS } from '../src/core/globals';
import nock from 'nock';

let rpDidDoc = {
    didDocument: {
        "@context": "https://w3id.org/did/v1",
        "id": "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83",
        "authentication": [
        {
            "type": "Secp256k1SignatureAuthentication2018",
            "publicKey": [
            "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83#controller"
            ]
        }
        ],
        "publicKey": [
        {
            "id": "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83#controller",
            "type": "Secp256k1VerificationKey2018",
            "ethereumAddress": "0xb07ead9717b44b6cf439c474362b9b0877cbbf83",
            "owner": "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83"
        }
        ]
    }
}
let rpDID = 'did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83';

let userDidDoc = {
    didDocument: {
        "@context": "https://w3id.org/did/v1",
        "id": "did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf",
        "authentication": [
        {
            "type": "Secp256k1SignatureAuthentication2018",
            "publicKey": [
            "did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf#controller"
            ]
        }
        ],
        "publicKey": [
        {
            "id": "did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf#controller",
            "type": "Secp256k1VerificationKey2018",
            "ethereumAddress": "0x30d1707aa439f215756d67300c95bb38b5646aef",
            "owner": "did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf"
        }
        ]
    }
  }
let userDID = 'did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf';

describe("Response", function () {
    beforeEach(() => {
        nock('https://uniresolver.io/1.0/identifiers').persist().get('/'+rpDID).reply(200, rpDidDoc).get('/'+userDID).reply(200, userDidDoc);
    });
    test("Response generation and validation", async () => {
        jest.setTimeout(7000);
        let requestPayload = {
            "iss": "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83",
            "response_type": "id_token",
            "client_id": "https://my.rp.com/cb",
            "scope": "openid did_authn",
            "state": "af0ifjsldkj",
            "nonce": "n-0S6_WzA2Mj",
            "response_mode": "form_post",
            "registration": {
                "jwks_uri": "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
                "id_token_signed_response_alg": ["ES256K", "ES256K-R", "EdDSA", "RS256"]
            }
        }
        let signing: SigningInfo = {
            alg: ALGORITHMS["ES256K-R"],
            key: 'CE438802C1F0B6F12BC6E686F372D7D495BC5AA634134B4A7EA4603CB25F0964',
            kid: 'did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83#controller',
            format: KEY_FORMATS.HEX,
        }

        let user = new Identity();
        await user.resolve('did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83')

        let response = await DidSiopResponse.generateResponse(requestPayload, signing, user, 5000);

        let checkParams = {
            redirect_uri: 'https://my.rp.com/cb',
            nonce: "n-0S6_WzA2Mj",
            validBefore: 1000,
            isExpirable: true,
        }
        let validity = await DidSiopResponse.validateResponse(response, checkParams);
        expect(validity).toBeTruthy();
    });
});