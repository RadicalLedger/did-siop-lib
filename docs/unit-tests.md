# Strategy for unit tests

## Test Data

Test Data for all test cases are available under ./test/data folder.

-   did-docs.testdata.ts
    All DID documents are inlcued in the TD_DID_DOCS structure

-   jwt.testdata.ts

-   key-pairs.testdata.ts
    Private and Public keys are available here. Same key is presented in many different formats to make the usage simple

-   common.testdata.ts
    Basic data structures for unit tests related to request/response generation/validation

-   request.testdata.ts
    This prepares different request data using the common.testdata.ts

### Data Categories

Following are the high level categories of test data used. Each category should have valid/invalid data to ensure the full coverage of testing.

-   DIDs and DID Documents
-   Tokens
    -   id_token
    -   vp_token
    -   claims
-   Request/Response
-   Parameters
-   JWTs

-   Keys
-   JWK, JWKS,
-   RSA, EC, OKP

-   Keys
-   JWK, JWKS,
-   RSA, ES256, ES256R, EdDSA
