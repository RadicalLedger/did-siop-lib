import { RP} from '../src/core/RP';
import {  ERRORS as ID_ERRORS } from '../src/core/Identity';
// import nock from 'nock';
import {DID_TEST_RESOLVER_DATA_NEW } from './did_doc.spec.resources'
import { ALGORITHMS,KEY_FORMATS } from '../src';
import { JWTObject, toJWTObject } from '../src/core/JWT';
import * as queryString from 'query-string';

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
    test("getRP shoud return an error if the DID is invalid ", async () => {
        let siop_rp = RP.getRP(
            redirect_uri, // RP's redirect_uri
            "not_a_did", // RP's did
            registration
        )
        await expect(siop_rp).rejects.toEqual(new Error(ID_ERRORS.DOCUMENT_RESOLUTION_ERROR));
        expect(siop_rp).not.toBe(null);            
    });
});

describe("RP related function with did:key crypto suite Ed25519VerificationKey2018", function() {
    jest.setTimeout(30000);
    test("getRP shoud return a valid RP instance with ", async () => {
        let siop_rp = await RP.getRP(
            redirect_uri, // RP's redirect_uri
            DID_TEST_RESOLVER_DATA_NEW[3].did, // RP's did
            registration
        )
        expect(siop_rp).not.toBe(null);

        siop_rp.addSigningParams(
            DID_TEST_RESOLVER_DATA_NEW[3].keyInfo.privateKey,
            DID_TEST_RESOLVER_DATA_NEW[3].keys[0].id,
            KEY_FORMATS.BASE58,
            ALGORITHMS['EdDSA']
        );
        let request = await siop_rp.generateRequest();
        expect(request).not.toBe(null);

        let parsed = queryString.parseUrl(request);   
        if ((parsed.query.request) && parsed.query.request !== undefined){        
            let req_jwt:JWTObject|undefined = toJWTObject(parsed.query.request.toString())
            expect(req_jwt).not.toEqual(undefined)

            if (req_jwt != undefined){
                expect(req_jwt.payload.iss).toEqual(DID_TEST_RESOLVER_DATA_NEW[3].did);
            }
        }
    });
});

describe("RP related function with did:key crypto suite Ed25519VerificationKey2020", function() {
    jest.setTimeout(30000);
    test("getRP shoud return a valid RP instance with ", async () => {
        let siop_rp = await RP.getRP(
            redirect_uri, // RP's redirect_uri
            DID_TEST_RESOLVER_DATA_NEW[4].did, // RP's did
            registration
        )
        expect(siop_rp).not.toBe(null);

        siop_rp.addSigningParams(
            DID_TEST_RESOLVER_DATA_NEW[4].keyInfo.privateKey,
            DID_TEST_RESOLVER_DATA_NEW[4].keys[0].id,
            KEY_FORMATS.BASE58,
            ALGORITHMS['EdDSA']
        );
        let request = await siop_rp.generateRequest();
        expect(request).not.toBe(null);

        let parsed = queryString.parseUrl(request);   
        if ((parsed.query.request) && parsed.query.request !== undefined){        
            let req_jwt:JWTObject|undefined = toJWTObject(parsed.query.request.toString())
            expect(req_jwt).not.toEqual(undefined)

            if (req_jwt != undefined){
                expect(req_jwt.payload.iss).toEqual(DID_TEST_RESOLVER_DATA_NEW[4].did);
            }
        }
    });
});