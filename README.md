# did-siop #

## Overview ##
This implements _Self Issued OpenId Connect Provider (SIOP)_ for _Decentralized Identities (DIDs)_. The library contains two components, **RP (Relying Party)** and **Provider**. Provider is intended to be used inside any piece of software which will provide DID SIOP authentication and RP can be used by relying parties (client apps) to utilize DID SIOP authentication. This library can be used in both client-side (browser) and server-side (Node.js) applications.

Following are the primary specifications followed by this implementation.
* [OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html#SelfIssued)
* [Self-Issued OpenID Connect Provider DID Profile](https://identity.foundation/did-siop/)

## Usage ##

### RP ###
```js
const DID_SIOP = require('did-siop');

const rp = await DID_SIOP.RP.getRP(
  'localhost:8080/home.html', // RP's redirect_uri
  'did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83', // RP's did
  {
    "jwks_uri": "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
    "id_token_signed_response_alg": ["ES256K-R", "EdDSA", "RS256"]
  } // RP's registration meta data
);
			
rp.addSigningParams(
  'CE438802C1F0B6F12BC6E686F372D7D495BC5AA634134B4A7EA4603CB25F0964', // Private key
  'did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83#owner', // Corresponding authentication method in RP's did document (to be used as kid value for key)
  DID_SIOP.KEY_FORMATS.HEX, //Format in which the key is supplied. List of values is given below
  DID_SIOP.ALGORITHMS['ES256K-R'] //Algorithm. List of values is given below
);// If several keys are provided, one will be selected randomly when generating the request. To remove a key use rp.removeSigningParams(kid)

//Request generation
rp.generateRequest([optionsObj]).then(request => {
  console.log(request);
})

//Response validation
rp.validateResponse(responseJWT).then(decodedResponse => {
  console.log(decodedResponse);
}).catch(err => {
  console.log('invalid response');
});
```

### Provider ###
```js
const DID_SIOP = require('did-siop');

const provider = new DID_SIOP.Provider();
await provider.setUser('did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf');// User's did

provider.addSigningParams(
  '3f81cb66c8cbba18fbe25f99d2fb4e19f54a1ee69c335ce756a705726189c9e7', // User's private key
  'did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf#owner', // Corresponding authentication method in user's did document (to be used as kid value for key)
  DID_SIOP.KEY_FORMATS.HEX, //Format in which the key is supplied. List of values is given below
  DID_SIOP.ALGORITHMS['ES256K-R'] //Algorithm. List of values is given below
);// If several keys are provided, one will be selected randomly when generating the request. To remove a key use provider.removeSigningParams(kid)

// Request validation and response generation
provider.validateRequest(request)
.then(decodedRequest => {
  let jwtExpiration = 5000;
  provider.generateResponse(decodedRequest.payload, [jwtExpiration])
  .then(responseJWT => {
    console.log(responseJWT);
  })
})
.catch(err => {
  console.log(invalid request);
})
```

### Supported Algorithms ###
Defined in _src/core/globals.ts_
* RS256, RS384, RS512
* PS256, PS384, PS512
* ES256, ES384, ES512, ES256K, ES256K-R, EdDSA

### Supported Key Formats ###
Defined in _src/core/globals.ts_
* PKCS8_PEM, PKCS1_PEM
* HEX, BASE58, BASE64

## Classes & Methods ##

### DID_SIOP ###
This class provides primary functionality to for Self Issued OpenIDConnect Provider.

---
#### setUser(did: string, doc?: DidDocument) ####
* Parameters
  * did:string - fully qualified decentralised identity of the user
  * doc?:DidDocument - Complete DID Document for the user [Optional]
* Return
  * void

Sets the user of the application. If the DID is provied, this function resolves the provided did to a DID Document

---
#### addSigningParams(key: string, kid: string, format: KEY_FORMATS, algorithm: ALGORITHMS) ####
Add necessary parameters for the user to cryptographically sign a message
* Parameters
  * key: string - Private Key of the user. Should match with one of the Keys provided in DID Document
  * kid: string - Key ID, should be one of the key ids in provided DID Document
  * format: KEY_FORMATS - One of the supported key formats (refer Supported Key Formats)
  * algorithm: ALGORITHMS - One of the supported algorithms (refer Supported Algorithms)
* Return
  * void

---
#### removeSigningParams(kid: string) ####
Removed already added key information for sigining
* Parameters
  * kid: string - Key ID of the key to be removed
* Return
  * void

---
#### validateRequest(request: string): Promise<JWTObject> ####
* Parameters
  * request: string - Authentication request from the user to sign in
* Return
  * Promise

---
#### generateResponse(requestPayload: any, expiresIn: number = 1000): Promise<string> ####
* Parameters
  * requestPayload: content of the response as JSON object
  * expiresIn: number - expiration time in seconds
* Return
  * Promise
---

### DID-SIOP-RP ###

#### getRP(redirect_uri: string, did: string, registration: any, did_doc?: DidDocument) ####

#### addSigningParams(key: string, kid: string, format: KEY_FORMATS, algorithm: ALGORITHMS) ####

#### removeSigningParams(kid: string) ####

#### generateRequest(options:any = {}): Promise<string> ####

#### generateUriRequest(request_uri: string, options:any = {}): Promise<string> ####

#### validateResponse(response: string, checkParams: CheckParams = {redirect_uri: this.info.redirect_uri}): Promise<any> ####


