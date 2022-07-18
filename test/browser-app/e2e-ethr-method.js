var count = 0;
var siopRequest, siopResponse;

import { TD_DID_DOCS } from "./data/did-docs.testdata";
// let userDidDoc = TD_DID_DOCS.ethr_rinkeby_1.didDocument;
let userDID = TD_DID_DOCS.ethr_rinkeby_1.didDocument.id;
let userPvtKey = TD_DID_DOCS.ethr_rinkeby_1.keys[0].privateKey;

// let rpDidDoc = TD_DID_DOCS.ethr_rinkeby_2.didDocument;
let rpDID = TD_DID_DOCS.ethr_rinkeby_2.didDocument.id;
let rpPvtKey = TD_DID_DOCS.ethr_rinkeby_2.keys[0].privateKey;

//Event bindings
document
  .getElementById("btnGenerateRequest")
  .addEventListener("click", function (event) {
    onButtonClick(event, this.id);
  });

document
  .getElementById("btnGenerateResponse")
  .addEventListener("click", function (event) {
    onButtonClick(event, this.id);
  });
document
  .getElementById("btnValidateResponse")
  .addEventListener("click", function (event) {
    onButtonClick(event, this.id);
  });

function onButtonClick(e, id) {
  switch (id) {
    case "btnGenerateRequest":
      generateRequest();
      break;
    case "btnGenerateResponse":
      generateResponse();
      break;
    case "btnValidateResponse":
      validateResponse();
      break;
  }
}

async function generateRequest() {
  console.log("generateRequest");

  let ethrResolver = new DID_SIOP.Resolvers.EthrDidResolver("ethr");
  // let keyResolv2018 = new DID_SIOP.Resolvers.KeyDidResolver(
  //   "key",
  //   "@digitalbazaar/x25519-key-agreement-key-2018"
  // );
  let siop_rp = await DID_SIOP.RP.getRP(
    "localhost:4200/home", // RP's redirect_uri
    rpDID, // RP's did
    {
      id_token_signed_response_alg: ["ES256K", "ES256K-R", "EdDSA", "RS256"],
    },
    undefined,
    [ethrResolver]
  );

  console.log(siop_rp);

  siop_rp.addSigningParams(rpPvtKey); // Private key
  console.log("RP SigningParams added ...");
  siopRequest = await siop_rp.generateRequest();

  console.log("Request generated ...", siopRequest);
  document.getElementById("generatedRequset").innerHTML = siopRequest;
}

async function generateResponse() {
  console.log("generateResponse");
  let ethrResolver = new DID_SIOP.Resolvers.EthrDidResolver("ethr");
  // let keyResolv2018 = new DID_SIOP.Resolvers.KeyDidResolver(
  //   "key",
  //   "@digitalbazaar/x25519-key-agreement-key-2018"
  // );
  const provider = await DID_SIOP.Provider.getProvider(userDID, undefined, [
    ethrResolver,
  ]);
  console.log("User DID set to Provider ...");

  provider.addSigningParams(userPvtKey); // User's private key

  console.log("User SigningParams added ...");

  // Request validation and response generation

  console.log("generateResponse::siopRequest=>>", siopRequest);

  provider
    .validateRequest(siopRequest)
    .then(async (decodedRequest) => {
      console.log("Request validation completed ...");
      console.log("decodedRequest", decodedRequest);

      document.getElementById("validatedRequset").innerHTML =
        JSON.stringify(decodedRequest);

      let jwtExpiration = 5000;
      try {
        await provider
          .generateResponse(decodedRequest.payload, jwtExpiration)
          .then((responseJWT) => {
            console.log("Response generated ...");
            siopResponse = responseJWT;
            console.log("responseJWT", siopResponse);
            document.getElementById("generatedResponse").innerHTML =
              JSON.stringify(siopResponse);
          });
      } catch (err) {
        console.log("ERROR provider.generateResponse  ", err);
      }
    })
    .catch((err) => {
      console.log("ERROR invalid request", err);
    });
}

async function validateResponse() {
  console.log("validateResponse");
  let ethrResolver = new DID_SIOP.Resolvers.EthrDidResolver("ethr");
  // let keyResolv2018 = new DID_SIOP.Resolvers.KeyDidResolver(
  //   "key",
  //   "@digitalbazaar/x25519-key-agreement-key-2018"
  // );
  let siop_rp = await DID_SIOP.RP.getRP(
    "localhost:4200/home", // RP's redirect_uri
    rpDID, // RP's did
    {
      id_token_signed_response_alg: ["ES256K", "ES256K-R", "EdDSA", "RS256"],
    },
    undefined,
    [ethrResolver]
  );

  console.log(siop_rp);

  siop_rp.addSigningParams(rpPvtKey);
  console.log("RP SigningParams added ...");
  let valid = await siop_rp.validateResponse(siopResponse);
  console.log("Response validated ...", valid);

  document.getElementById("validatedResponse").innerHTML =
    JSON.stringify(valid);
}
