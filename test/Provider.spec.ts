import { JWTObject } from '../src/core/JWT';
import nock from 'nock';
import {DID_TEST_RESOLVER_DATA_NEW as DIDS } from './did_doc.spec.resources'
import { RP} from '../src/core/RP';
import { Provider} from '../src/core/Provider';
import {  EthrDidResolver } from '../src/core/Identity/Resolvers/did_resolver_ethr';

let userDidDoc  = DIDS[0].resolverReturn.didDocument;
let userKeyInfo = DIDS[0].keyInfo;
let userDID     = DIDS[0].did;
let userPrivateKeyHex = userKeyInfo.privateKey;
let userKid = userDidDoc.verificationMethod[1].id;

let rpDidDoc = DIDS[1].resolverReturn.didDocument;
let rpDID = DIDS[1].did;
let rpKeyInfo = DIDS[1].keyInfo;
let rpPrivateKey = rpKeyInfo.privateKey;
let rpKid = rpDidDoc.verificationMethod[1].id;;

let rpRedirectURI = 'https://my.rp.com/cb';
let rpRegistrationMetaData = {
        "jwks_uri": "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
        "id_token_signed_response_alg": ["ES256K", "ES256K-R", "EdDSA", "RS256"]
};

let requestObj: JWTObject = {
    header: {
        "alg": "ES256K",
        "typ": "JWT",
        "kid": rpKid
    },
    payload:{
        "iss": rpDID,
        "response_type": "id_token",
        "scope": "openid did_authn",
        "client_id": rpDID,
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

describe('005 Provider testing with dynamically added resolver', function () {
    beforeEach(() => {
        nock('https://uniresolver.io/1.0/identifiers').persist().get('/'+rpDID).reply(200, rpDidDoc).get('/'+userDID).reply(200, userDidDoc);
    });
    test('a. with did:ethr resolver', async () => {
        jest.setTimeout(30000);

        let ethrResolver = new EthrDidResolver('ethr');

        let rp = await RP.getRP(rpRedirectURI, rpDID, rpRegistrationMetaData,undefined,[ethrResolver]);
        let kid = rp.addSigningParams(rpPrivateKey);
        expect(kid).toEqual(rpKid);

        let provider = new Provider();
        await provider.setUser(userDID);
        kid = provider.addSigningParams(userPrivateKeyHex);
        expect(kid).toEqual(userKid);

        let request =  await rp.generateRequest();
        let requestJWTDecoded = await provider.validateRequest(request,undefined, [ethrResolver]);
        expect(requestJWTDecoded).toMatchObject(requestObj);

        let response = await provider.generateResponse(requestJWTDecoded.payload);
        let responseJWTDecoded = await rp.validateResponse(response, {
            redirect_uri: rpRedirectURI,
            isExpirable: true,
        },
        [ethrResolver])
        expect(responseJWTDecoded).toHaveProperty('header');
        expect(responseJWTDecoded).toHaveProperty('payload');
    });
});

