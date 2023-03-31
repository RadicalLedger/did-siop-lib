# did-siop

## Overview

This implements _Self Issued OpenId Connect Provider (SIOP) V2_. The library contains two components, **RP (Relying Party)** and **Provider**. Provider is intended to be use inside any piece of software which will provide DID SIOP authentication (Identity Wallet) and RP can be used by relying parties (client applications) to employ DID SIOP authentication. This library can be used in both client-side (browser) and server-side (Node.js) applications.

Following are the primary specifications followed by this implementation.

### Specifications

-   [Self-Issued OpenID Provider v2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)
-   [OpenID Connect for Verifiable Presentations](https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0.html)

### Availability

-   [For Node](https://www.npmjs.com/package/did-siop)
-   [For Browser](https://cdn.jsdelivr.net/npm/did-siop@2.0.3/dist/browser/did-siop.min.js)

## Documentation

-   [API Documentation](./docs/api-documentation.md)

## Capabiltities

### Static SIOP Discovery Metadata

By defalut, library uses [specified](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#name-static-self-issued-openid-p) Discovery metadata, but also provides a mechanism to use custom values.

#### Initialise RP with Metadata

```js
        // get default set of metadata
        let temp_md:SiopMetadataSupported = {...SIOP_METADATA_SUPPORTED}
        // set scopes to "openid" and "did_authn"
        temp_md.scopes = ["openid" "did_authn"];

        let keyResolv2018 = new KeyDidResolver('key', CRYPTO_SUITES.Ed25519VerificationKey2018);
        let siop_rp = await RP.getRP(
            redirect_uri, // RP's redirect_uri
            DID_TEST_RESOLVER_DATA_NEW[3].did, // RP's did
            registration,
            temp_md, // use custom Metadata to initialise the RP
            [keyResolv2018]
        )

```

#### Validate Metadata

```js
        // get default set of metadata
        let temp_md:SiopMetadataSupported = {...SIOP_METADATA_SUPPORTED}

        // set scopes supported to "openid" only, so the request validate must have "openid" as scope
        temp_md.scopes = ["openid];

        // use the new metadata set to validate the request
        let validityPromise =  DidSiopRequest.validateRequest(requests.good.requestGoodEmbeddedJWT,temp_md);

```

### DID Resolvers

Version 2 of did-siop provides mechanism to use custom DID Resolvers. Currently resolvers for following DID Methods are built in, but developers have the option to write thier own resolvers.

-   EthrDidResolver [did:ethr](https://github.com/RadicalLedger/did-siop-lib/blob/dev/src/core/identity/resolvers/did_resolver_ethr.ts)
-   KeyDidResolver [did:key](https://github.com/RadicalLedger/did-siop-lib/blob/dev/src/core/identity/resolvers/did_resolver_key.ts)
-   UniversalDidResolver [did:\*](https://github.com/RadicalLedger/did-siop-lib/blob/dev/src/core/identity/resolvers/did_resolver_uniresolver.ts) - DID Methods supported by https://dev.uniresolver.io/

To build a custom resolver to use with DID-SIOP, derive your custom resolver from [DidResolver](https://github.com/RadicalLedger/did-siop-lib/blob/dev/src/core/identity/resolvers/did_resolver_base.ts) and override the **resolveDidDocumet** appropriately.

#### Working with Resolvers

Default behavior of this library does not need any Resolvers to be specified. In absence of an external Resolver, library uses **UniversalDidResolver** which relies on https://dev.uniresolver.io/ (Please note, availability of https://dev.uniresolver.io/ is not consistent and do not advise to use it in live applications).

At the time of creating a **RP** or **Provider** instance, along with the DID, it is possible to specify an array of Resolvers that should be used to resolve the given DID. These resolvers must be derived from DidResolver baseclass. Once specified a set of resolvers at the time of creating RP or Provider instance, subsequent requirements of DID resolutions in that instance will use the provided resolvers. In addition to this, it is possible to specify an array of resolvers in following methods which overrised the instance level resolver list.

-   RP:validateResponse
-   RP:validateResponseWithVPData
-   Provider:validateRequest

#### Crypto Suites

When using/building a resolver, the library provide the option of specifying a **Crypto Suite** to be used in resolving DIDs. Relevant Crypto Suite can be passed as an argument when constructing the DIDResolver.

```js
let keyResolv2018 = new KeyDidResolver('key', CRYPTO_SUITES.Ed25519VerificationKey2018);
let siop_rp = await RP.getRP(
    redirect_uri, // RP's redirect_uri
    DID_TEST_RESOLVER_DATA_NEW[3].did, // RP's did
    registration,
    undefined,
    [keyResolv2018]
);
```

DID-SIOP has been tested the KeyDidResolver using following Crypto-Suites.

-   @digitalbazaar/ed25519-verification-key-2018
-   @digitalbazaar/ed25519-verification-key-2020

## Special Data Structures

#### VPData

When generating a response with **Provider.generateResponseWithVPData**, matching Presentation Data for the vp_data parameter of Claims will be submitted using this data structure.

```js
export interface VPData {
    vp_token: any; // JSON object with VP related data
    _vp_token: any; // JSON object wit VP request related info
}
```

#### SIOPTokensEcoded

When generating a response with **Provider.generateResponseWithVPData** , data is returned using this data structure. Both ID_Token and VP_Token are presended as Base64 encoded JWTs

```js
export interface SIOPTokensEcoded {
    id_token: string; // Base64 encoded JWT
    vp_token: string; // Base64 encoded JWT
}
```

#### SIOPTokenObjects

When validating a response with **Provider.validateResponseWithVPData** , method returns using this data structure. Both ID_Token and VP_Token are presended as JWTs

```js
export interface SIOPTokenObjects {
    id_token: any; // Decoded Object
    vp_token: any; // Decoded Object
}
```

## Usage

Sample illustrating the usage of basic funcitons of [did-siop](https://github.com/RadicalLedger/did-siop-lib/tree/master) library can be found [here](https://github.com/RadicalLedger/siop-auth-sample)

### RP

```js
//Request Generation
var request;
siop_rp = await DID_SIOP.RP.getRP(
    'localhost:5001/home', // RP's redirect_uri
    'did:ethr:rinkeby:0x02be73dcaa2013a714b6745f54ff8576df151f8226cc3923538bfbfb9a014584fe', // RP's did
    {
        jwks_uri: 'https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks',
        id_token_signed_response_alg: ['ES256K', 'EdDSA', 'RS256']
    }
);
console.log('Got RP instance ....');
siop_rp.addSigningParams('c4873e901915343baf7302b0b87bae70bf5726e9280d415b3f7fc85908cc9d5a'); // Private key

console.log('RP SigningParams added ...');
request = await siop_rp.generateRequest();

console.log('Request generated ...', request);

//Response validation
const validateResponse = async () => {
    console.log('onRP');
    let keyResolv2020 = new SIOP.Resolvers.KeyDidResolver(
        'key',
        '@digitalbazaar/x25519-key-agreement-key-2018'
    );
    let siop_rp = await SIOP.RP.getRP(
        'localhost:4200/home', // RP's redirect_uri
        'did:key:z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw', // RP's did
        {
            id_token_signed_response_alg: ['ES256K', 'ES256K-R', 'EdDSA', 'RS256']
        },
        undefined,
        [keyResolv2020]
    );

    console.log(siop_rp);

    siop_rp.addSigningParams(
        'zrv1xdp8ZsfXSDh4fQp8sE2VYPmLiCL3RssjKeXW7fYrRkxyWpWR5ugcC36WrCx9FizbJvxdwFmYcq7YxRVC2nVPFp5'
    ); // Private key

    console.log('RP SigningParams added ...');
    let valid = await siop_rp.validateResponse(props.response);
    console.log('Response validated ...', valid);
    setResponse(valid);
};
```

### Provider

```js
// Response Generation
const DID_SIOP = require('did-siop');

const generateResponse = async () => {
    let provider = await Provider.getProvider(
        'did:key:z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw'
    );
    console.log('Got Provider instance with User DID...');
    provider.addSigningParams(
        'zrv1xdp8ZsfXSDh4fQp8sE2VYPmLiCL3RssjKeXW7fYrRkxyWpWR5ugcC36WrCx9FizbJvxdwFmYcq7YxRVC2nVPFp5'
    ); // User's private key

    console.log('User SigningParams added ...');

    // Request validation and response generation
    console.log('props.request=>>', props.request);
    provider
        .validateRequest(props.request)
        .then(async (decodedRequest) => {
            console.log('Request validation completed ...');
            console.log('decodedRequest', decodedRequest);
            let jwtExpiration = 5000;
            try {
                await provider
                    .generateResponse(decodedRequest.payload, jwtExpiration)
                    .then((responseJWT) => {
                        console.log('Response generated ...');
                        console.log('responseJWT', responseJWT);
                    });
            } catch (err) {
                console.log('ERROR provider.generateResponse  ', err);
            }
        })
        .catch((err) => {
            console.log('ERROR invalid request', err);
        });
};
```

### Supported Algorithms

Defined in _src/core/globals.ts_

-   RS256, RS384, RS512
-   PS256, PS384, PS512
-   ES256, ES384, ES512, ES256K, ES256K-R, EdDSA

### Supported Key Formats

Defined in _src/core/globals.ts_

-   PKCS8_PEM, PKCS1_PEM
-   HEX, BASE58, BASE64

## Verifiable Presentations (VP)

### Request VPs

In the request, **vp_token** attribute could appear within the claims attribute. This should have have the **presentation_definition** attribute as a child element.

Sample vp_token (for requesting VPs) :

```
    "vp_token": {
        "presentation_definition": {
            "id": "vp token example",
            "input_descriptors": [
                {
                    "id": "id card credential",
                    "format": {
                        "ldp_vc": {
                            "proof_type": [
                                "Ed25519Signature2018"
                            ]
                        }
                    },
                    "constraints": {
                        "fields": [
                            {
                                "path": [
                                    "$.type"
                                ],
                                "filter": {
                                    "type": "string",
                                    "pattern": "IDCardCredential"
                                }
                            }
                        ]
                    }
                }
            ]
        }
    }
```

### VPs in Response

**vp_token** will be included in the same response as ID Token and will be a separate element in the same level as ID Token. In this implementation, **vp_token** is an Base64 encoded JWT.
Along with **vp_token**, there coudl be a \_vp_token attribute inside the **id_token**. Purpose of this is to give an indication about what VPs were requested at the request.

Sample \_vp_token :

```
    "_vp_token": {
        "presentation_submission": {
            "id": "Selective disclosure example presentation",
            "definition_id": "Selective disclosure example",
            "descriptor_map": [
                {
                    "id": "ID Card with constraints",
                    "format": "ldp_vp",
                    "path": "$",
                    "path_nested": {
                        "format": "ldp_vc",
                        "path": "$.verifiableCredential[0]"
                    }
                }
            ]
        }
    }
```

Sample vp_token (in response) :

```
    id_token :{
      <id_token content>
    },
    vp_token : {
        "@context": [
            "https://www.w3.org/2018/credentials/v1"
        ],
        "type": [
            "VerifiablePresentation"
        ],
        "verifiableCredential": [
            {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1"
                ],
                "id": "https://example.com/credentials/1872",
                "type": [
                    "VerifiableCredential",
                    "IDCardCredential"
                ],
                "issuer": {
                    "id": "did:example:issuer"
                },
                "issuanceDate": "2010-01-01T19:23:24Z",
                "credentialSubject": {
                    "given_name": "Fredrik",
                    "family_name": "Str&#246;mberg",
                    "birthdate": "1949-01-22"
                },
                "proof": {
                    "type": "Ed25519Signature2018",
                    "created": "2021-03-19T15:30:15Z",
                    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PT8yCqVjj5ZHD0W36zsBQ47oc3El07WGPWaLUuBTOT48IgKI5HDoiFUt9idChT_Zh5s8cF_2cSRWELuD8JQdBw",
                    "proofPurpose": "assertionMethod",
                    "verificationMethod": "did:example:issuer#keys-1"
                }
            }
        ],
        "id": "ebc6f1c2",
        "holder": "did:example:holder",
        "proof": {
            "type": "Ed25519Signature2018",
            "created": "2021-03-19T15:30:15Z",
            "challenge": "n-0S6_WzA2Mj",
            "domain": "https://client.example.org/cb",
            "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..GF5Z6TamgNE8QjE3RbiDOj3n_t25_1K7NVWMUASe_OEzQV63GaKdu235MCS3hIYvepcNdQ_ZOKpGNCf0vIAoDA",
            "proofPurpose": "authentication",
            "verificationMethod": "did:example:holder#key-1"
        }
    }
```

### Code Samples

Find how to use SIOP with VP Data [here](https://github.com/RadicalLedger/siop-auth-sample/blob/main/src/auth_vpdata_method_key.ts)

### Test Cases

Test cases depend on the availabiltiy of https://dev.uniresolver.io/ (which goes offline time to time). If test cases are failing, check the availabiltiy of Uniresolver before troubshoot.

#### Tesing on Browser

`test\browser-app` has html and js files which runs without any other dependencies. These files should refer `dist/browser/did-siop.min.js` when implementing DID-SIOP related functions. [puppeteer](https://pptr.dev/) is used in headless mode with jest to run tests.

Use the following folder structure and naming covention when adding more tests.

```
test
|browser-e2e-minimum.spec.ts
|-- browser-app
    | e2e-minimum.html
    | e2e-minimum.js
```

### Code Formatting

[prettier](https://prettier.io/) is setup for code foramtting. This has been setup with [husky & pretty-quick](https://prettier.io/docs/en/precommit.html#option-2-pretty-quickhttpsgithubcomazzpretty-quick) to do the formatting at each commit.

### Hot Fix

**This is necessarry only if you are building custom apps using did-siop-lib with older versions of TypeScript**
chaneg following line in node_modules/ethr-did-resolver/lib/index.js (ln1087)

```
    // blockTag = qParams.get('versionId') ?? blockTag;
    blockTag = ((qParams.get('versionId') == null) || qParams.get('versionId') == undefined) ? blockTag : qParams.get('versionId');
```
