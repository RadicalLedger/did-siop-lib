import { JWTObject } from "../src/core/jwt";
import { RP } from "../src/core/rp";
import { Provider } from "../src/core/provider";
import { TD_BASIC_JWT, TD_REQUESTS } from "./data/request.testdata";
import { getModifiedJWT } from "./data/common.testdata";
import { PROVIDER_TD } from "./data/provider.testdata";

const rpDID = PROVIDER_TD.rp.didDocument.id;
const rpPrivateKey = PROVIDER_TD.rp.keys[0].privateKey;
const rpKid = PROVIDER_TD.rp.didDocument.verificationMethod[1].id;
const rpResolver = PROVIDER_TD.rp.resolver;

let rpRedirectURI = TD_REQUESTS.components.rp.redirect_uri;
let rpRegistrationMetaData = TD_REQUESTS.components.rp.registration;
let requestObj: JWTObject = TD_BASIC_JWT.decoded;

// Prepare  the reqiest for RP.generateRequest() without any parameters
requestObj = getModifiedJWT(TD_BASIC_JWT.decoded, true, "nonce", null); // Remove nonce
requestObj = getModifiedJWT(requestObj, true, "response_mode", null); // Remove response_mode
requestObj = getModifiedJWT(requestObj, true, "state", null); // // Remove state
requestObj = getModifiedJWT(requestObj, true, "redirect_uri", null); // // Remove redirect_uri

//Set the default timeout interval to 30000 ms for all tests and before/after hooks
jest.setTimeout(30000);

describe("006 Provider testing with dynamically added resolver", function () {
  test("a. with did:ethr resolver", async () => {
    let rp = await RP.getRP(
      rpRedirectURI,
      rpDID,
      rpRegistrationMetaData,
      undefined,
      [rpResolver]
    );
    let kid = rp.addSigningParams(rpPrivateKey);
    expect(kid).toEqual(rpKid);

    let provider = await Provider.getProvider(rpDID, undefined, [rpResolver]);
    kid = provider.addSigningParams(rpPrivateKey);
    expect(kid).toEqual(rpKid);

    let request = await rp.generateRequest();
    let requestJWTDecoded = await provider.validateRequest(request);
    expect(requestJWTDecoded).toMatchObject(requestObj);

    let response = await provider.generateResponse(requestJWTDecoded.payload);
    let responseJWTDecoded = await rp.validateResponse(response, {
      redirect_uri: rpRedirectURI,
      isExpirable: true,
    });
    expect(responseJWTDecoded).toHaveProperty("header");
    expect(responseJWTDecoded).toHaveProperty("payload");
  });
});
