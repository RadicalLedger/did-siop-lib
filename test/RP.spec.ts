import { RP} from '../src/core/RP';
import {  ERRORS as ID_ERRORS } from '../src/core/Identity';
// import nock from 'nock';
import {DID_TEST_RESOLVER_DATA_NEW } from './did_doc.spec.resources'

let registration = {
        "jwks_uri": "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
        "id_token_signed_response_alg": ["ES256K-R", "EdDSA", "RS256"]
        };
let redirect_uri : 'localhost:4200/home';

describe("RP related function with did:ethr ", function() {
    jest.setTimeout(30000);
    test("getRP shoud return a valid RP instance with ", async () => {
        let siop_rp = await RP.getRP(
            redirect_uri, // RP's redirect_uri
            DID_TEST_RESOLVER_DATA_NEW[0].did, // RP's did
            registration
        )
        expect(siop_rp).not.toBe(null);            
    });
    test("getRP shoud return an if the DID is invalid ", async () => {
        let siop_rp = RP.getRP(
            redirect_uri, // RP's redirect_uri
            "not_a_did", // RP's did
            registration
        )
        await expect(siop_rp).rejects.toEqual(new Error(ID_ERRORS.DOCUMENT_RESOLUTION_ERROR));
        expect(siop_rp).not.toBe(null);            
    });
});

describe("RP related function with did:key ", function() {
    jest.setTimeout(30000);
    test("getRP shoud return a valid RP instance with ", async () => {
        let siop_rp = await RP.getRP(
            redirect_uri, // RP's redirect_uri
            DID_TEST_RESOLVER_DATA_NEW[2].did, // RP's did
            registration
        )
        expect(siop_rp).not.toBe(null);            
    });
});