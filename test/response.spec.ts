import { DidSiopResponse } from '../src/core/Response';
import { Identity } from '../src/core/Identity';
import { SigningInfo } from '../src/core/JWT';
import { ALGORITHMS, KEY_FORMATS } from '../src/core/globals';
import nock from 'nock';
import { requestJWT } from './response.spec.resources';
import {DID_TEST_RESOLVER_DATA_NEW as DIDS } from './did_doc.spec.resources'

let userDidDoc  = DIDS[0].resolverReturn.didDocument;
let userDID     = DIDS[0].did;
let userKeyInfo = DIDS[0].keyInfo;

let rpDidDoc    = DIDS[1].resolverReturn.didDocument;
let rpDID       = DIDS[1].did;

let signing: SigningInfo = {
    alg: ALGORITHMS["ES256K"],
    kid: userDidDoc.verificationMethod[1].id,
    key: userKeyInfo.privateKey,
    format: KEY_FORMATS.HEX,
}

let checkParams = {
    redirect_uri: 'https://my.rp.com/cb',
    nonce: "n-0S6_WzA2Mj",
    validBefore: 30000,
    isExpirable: true,
}

describe("Response", function () {
    beforeEach(() => {
        nock('https://uniresolver.io/1.0/identifiers').persist().get('/'+rpDID).reply(200, rpDidDoc).get('/'+userDID).reply(200, userDidDoc);
    });
    test("with basic info : generation and validation", async () => {
        jest.setTimeout(30000);
        let user = new Identity();
        await user.resolve(userDID)

        let response = await DidSiopResponse.generateResponse(requestJWT.good.basic.payload, signing, user, 30000);
        let validity = await DidSiopResponse.validateResponse(response, checkParams);
        expect(validity).toBeTruthy();
    });
    test(" with valid vp_token : generation and validation", async () => {
        jest.setTimeout(30000);
        let user = new Identity();
        await user.resolve(userDID)

        let response = await DidSiopResponse.generateResponse(requestJWT.good.withVPToken.payload, signing, user, 30000);
        let validity = await DidSiopResponse.validateResponse(response, checkParams);
        expect(validity).toBeTruthy();
    });    
});