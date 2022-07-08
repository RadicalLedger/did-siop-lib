import { getBasicJWT, getModifiedJWT, claims } from "./common.spec.resources";
import { TD_DID_DOCS } from "./data/did-docs.testdata";

let testDidDoc = TD_DID_DOCS.ethr_rinkeby_1.didDocument;
let testDID = TD_DID_DOCS.ethr_rinkeby_1.didDocument.id;

const jwtGoodDecoded = getBasicJWT(
  testDidDoc.verificationMethod[1].id,
  testDID,
  testDID
);

export const requestJWT = {
  good: {
    basic: jwtGoodDecoded,
    withVPToken: getModifiedJWT(jwtGoodDecoded, true, "claims", claims.good),
  },
  bad: {
    withVPToken: getModifiedJWT(jwtGoodDecoded, true, "claims", claims.bad),
  },
};
