import { RP } from "../src/core/rp";
import { ERRORS as ID_ERRORS } from "../src/core/identity";
import { JWTObject, toJWTObject } from "../src/core/jwt";
import * as queryString from "query-string";
import { TD_REQUESTS } from "./data/request.testdata";
import { RP_TD } from "./data/rp.testdata";

let siop_rp: any;
const redirect_uri = TD_REQUESTS.components.rp.redirect_uri;
const registration = TD_REQUESTS.components.rp.registration;

//Set the default timeout interval to 30000 ms for all tests and before/after hooks
jest.setTimeout(30000);

describe.each(RP_TD.didDocs)(
  "005.01 RP related function with ($tag)",
  ({ resolver, didDocument, keys }) => {
    // const rpDidDoc = data.rp.didDocument;
    const rpDID = didDocument.id;
    const rpPrivateKey = keys[0].privateKey;
    const rpKeyFormat = keys[0].format;
    const rpKeyAlg = keys[0].alg;

    test("a. getRP should return a valid RP instance with DID", async () => {
      siop_rp = await RP.getRP(
        redirect_uri, // RP's redirect_uri
        rpDID, // RP's did
        registration,
        undefined,
        [resolver]
      );
      expect(siop_rp).not.toBe(null);

      siop_rp.addSigningParams(rpPrivateKey, rpDID, rpKeyFormat, rpKeyAlg);

      const request = await siop_rp.generateRequest();
      expect(request).not.toBe(null);

      const parsed = queryString.parseUrl(request);
      if (parsed.query.request && parsed.query.request !== undefined) {
        const req_jwt: JWTObject | undefined = toJWTObject(
          parsed.query.request.toString()
        );
        expect(req_jwt).not.toEqual(undefined);

        if (req_jwt != undefined) {
          expect(req_jwt.payload.iss).toEqual(rpDID);
        }
      }
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
  }
);
