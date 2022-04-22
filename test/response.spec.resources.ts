import { getBasicJWT, getModifiedJWT, claims } from './common.spec.resources';
import {DID_TEST_RESOLVER_DATA_NEW as DIDS } from './did_doc.spec.resources'

let testDidDoc  = DIDS[0].resolverReturn.didDocument;
let testDID     = DIDS[0].did;

const jwtGoodDecoded = getBasicJWT(testDidDoc.verificationMethod[1].id,testDID);

export const requestJWT = {
    good :{
        basic : jwtGoodDecoded,
        withVPToken : getModifiedJWT(jwtGoodDecoded, true, 'claims',claims.good),
    },
    bad:{
        withVPToken : getModifiedJWT(jwtGoodDecoded, true, 'claims',claims.bad),
    }

}