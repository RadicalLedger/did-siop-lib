import { CRYPTO_SUITES } from "../src/core/globals";
import { RP } from "../src/core/rp";
import { ERRORS as ID_ERRORS } from "../src/core/identity";
import { KeyDidResolver } from "../src/core/identity/resolvers/did-resolver-key";
import { TD_DID_DOCS } from "./data/did-docs.testdata";
import { ALGORITHMS, KEY_FORMATS } from "../src";
import { JWTObject, toJWTObject } from "../src/core/jwt";
import * as queryString from "query-string";
import { TD_REQUESTS } from "./data/request.testdata";
import { DidResolvers } from "../src/core/identity/resolvers/did-resolvers";
import { rp } from "./data/rp.testdata";

let siop_rp: any;
let redirect_uri = TD_REQUESTS.components.rp.redirect_uri;
let registration = TD_REQUESTS.components.rp.registration;

//Set the default timeout interval to 30000 ms for all tests and before/after hooks
jest.setTimeout(30000);

describe.only.each(rp)("($tag)", ({ tag, resolver, didDocument, keys }) => {
  describe(`005.01 RP related function with ${tag}`, () => {
    // const rpDidDoc = data.rp.didDocument;
    const rpDID = didDocument.id;
    const rpPrivateKey = keys[0].privateKey;
    const rpKeyFormat = keys[0].format;
    const rpKeyAlg = keys[0].alg;

    test("a. getRP should return a valid RP instance with ", async () => {
      siop_rp = await RP.getRP(
        redirect_uri, // RP's redirect_uri
        rpDID, // RP's did
        registration,
        undefined,
        [resolver]
      );
      expect(siop_rp).not.toBe(null);

      siop_rp.addSigningParams(rpPrivateKey, rpDID, rpKeyFormat, rpKeyAlg);

      let request = await siop_rp.generateRequest();
      expect(request).not.toBe(null);

      let parsed = queryString.parseUrl(request);
      if (parsed.query.request && parsed.query.request !== undefined) {
        let req_jwt: JWTObject | undefined = toJWTObject(
          parsed.query.request.toString()
        );
        expect(req_jwt).not.toEqual(undefined);

        if (req_jwt != undefined) {
          expect(req_jwt.payload.iss).toEqual(rpDID);
        }
      }
    });
  });
});

describe("005.01 RP related function with did:ethr ", function () {
  test("a. getRP should return a valid RP instance", async () => {
    siop_rp = await RP.getRP(
      redirect_uri, // RP's redirect_uri
      TD_DID_DOCS.ethr_rinkeby_1.didDocument.id, // RP's did
      registration
    );
    expect(siop_rp).not.toBe(null);
  });
  test("b. getRP should return an error if the DID is invalid ", async () => {
    siop_rp = RP.getRP(
      redirect_uri, // RP's redirect_uri
      "not_a_did", // RP's did
      registration
    );
    await expect(siop_rp).rejects.toEqual(
      new Error(ID_ERRORS.DOCUMENT_RESOLUTION_ERROR)
    );
    expect(siop_rp).not.toBe(null);
  });
});

describe("005.02 RP related function with did:key crypto suite Ed25519VerificationKey2018", function () {
  test("a. getRP should return a valid RP instance with ", async () => {
    let keyResolv2018 = new KeyDidResolver(
      "key",
      CRYPTO_SUITES.Ed25519VerificationKey2018
    );
    siop_rp = await RP.getRP(
      redirect_uri, // RP's redirect_uri
      TD_DID_DOCS.key_2018_2.didDocument.id, // RP's did
      registration,
      undefined,
      [keyResolv2018]
    );
    expect(siop_rp).not.toBe(null);

    siop_rp.addSigningParams(
      TD_DID_DOCS.key_2018_2.keys[0].privateKey,
      TD_DID_DOCS.key_2018_2.keys[0].id,
      KEY_FORMATS.BASE58,
      ALGORITHMS["EdDSA"]
    );

    let request = await siop_rp.generateRequest();
    expect(request).not.toBe(null);

    let parsed = queryString.parseUrl(request);
    if (parsed.query.request && parsed.query.request !== undefined) {
      let req_jwt: JWTObject | undefined = toJWTObject(
        parsed.query.request.toString()
      );
      expect(req_jwt).not.toEqual(undefined);

      if (req_jwt != undefined) {
        expect(req_jwt.payload.iss).toEqual(
          TD_DID_DOCS.key_2018_2.didDocument.id
        );
      }
    }
  });
});

describe("005.03 RP related function with did:key crypto suite Ed25519VerificationKey2020", function () {
  test("a. getRP should return a valid RP instance with ", async () => {
    let keyResolv2020 = new KeyDidResolver(
      "key",
      CRYPTO_SUITES.Ed25519VerificationKey2020
    );
    siop_rp = await RP.getRP(
      redirect_uri, // RP's redirect_uri
      TD_DID_DOCS.key_2020_1.didDocument.id, // RP's did
      registration,
      undefined,
      [keyResolv2020]
    );

    siop_rp.addSigningParams(
      TD_DID_DOCS.key_2020_1.keys[0].privateKey,
      TD_DID_DOCS.key_2020_1.keys[0].id,
      KEY_FORMATS.BASE58,
      ALGORITHMS["EdDSA"]
    );
    expect(siop_rp).not.toBe(null);

    let request = await siop_rp.generateRequest();
    expect(request).not.toBe(null);

    let parsed = queryString.parseUrl(request);
    if (parsed.query.request && parsed.query.request !== undefined) {
      let req_jwt: JWTObject | undefined = toJWTObject(
        parsed.query.request.toString()
      );
      expect(req_jwt).not.toEqual(undefined);

      if (req_jwt != undefined) {
        expect(req_jwt.payload.iss).toEqual(
          TD_DID_DOCS.key_2020_1.didDocument.id
        );
      }
    }
  });
});
