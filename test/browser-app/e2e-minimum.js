var count = 0;
var siopRequest, siopResponse;

//Event bindings
document.getElementById('btnGenerateRequest').addEventListener('click', function (event) {
    onButtonClick(event, this.id);
});

document.getElementById('btnGenerateResponse').addEventListener('click', function (event) {
    onButtonClick(event, this.id);
});
document.getElementById('btnValidateResponse').addEventListener('click', function (event) {
    onButtonClick(event, this.id);
});

function onButtonClick(e, id) {
    switch (id) {
        case 'btnGenerateRequest':
            generateRequest();
            break;
        case 'btnGenerateResponse':
            generateResponse();
            break;
        case 'btnValidateResponse':
            validateResponse();
            break;
    }
}

async function generateRequest() {
    console.log('generateRequest');

    let keyResolv2018 = new DID_SIOP.Resolvers.KeyDidResolver(
        'key',
        '@digitalbazaar/x25519-key-agreement-key-2018'
    );
    let siop_rp = await DID_SIOP.RP.getRP(
        'localhost:4200/home', // RP's redirect_uri
        'did:key:z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw', // RP's did
        {
            id_token_signed_response_alg: ['ES256K', 'ES256K-R', 'EdDSA', 'RS256']
        },
        undefined,
        [keyResolv2018]
    );

    console.log(siop_rp);

    siop_rp.addSigningParams(
        'zrv1xdp8ZsfXSDh4fQp8sE2VYPmLiCL3RssjKeXW7fYrRkxyWpWR5ugcC36WrCx9FizbJvxdwFmYcq7YxRVC2nVPFp5'
    ); // Private key
    console.log('RP SigningParams added ...');
    siopRequest = await siop_rp.generateRequest();

    console.log('Request generated ...', siopRequest);
    document.getElementById('generatedRequset').innerHTML = siopRequest;
}

async function generateResponse() {
    console.log('generateResponse');
    let keyResolv2018 = new DID_SIOP.Resolvers.KeyDidResolver(
        'key',
        '@digitalbazaar/x25519-key-agreement-key-2018'
    );
    const provider = await DID_SIOP.Provider.getProvider(
        'did:key:z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw',
        undefined,
        [keyResolv2018]
    );
    console.log('User DID set to Provider ...');

    provider.addSigningParams(
        'zrv1xdp8ZsfXSDh4fQp8sE2VYPmLiCL3RssjKeXW7fYrRkxyWpWR5ugcC36WrCx9FizbJvxdwFmYcq7YxRVC2nVPFp5'
    ); // User's private key

    console.log('User SigningParams added ...');

    // Request validation and response generation

    console.log('generateResponse::siopRequest=>>', siopRequest);

    provider
        .validateRequest(siopRequest)
        .then(async (decodedRequest) => {
            console.log('Request validation completed ...');
            console.log('decodedRequest', decodedRequest);

            document.getElementById('validatedRequset').innerHTML = JSON.stringify(decodedRequest);

            let jwtExpiration = 5000;
            try {
                await provider
                    .generateResponse(decodedRequest.payload, jwtExpiration)
                    .then((responseJWT) => {
                        console.log('Response generated ...');
                        siopResponse = responseJWT;
                        console.log('responseJWT', siopResponse);
                        document.getElementById('generatedResponse').innerHTML =
                            JSON.stringify(siopResponse);
                    });
            } catch (err) {
                console.log('ERROR provider.generateResponse  ', err);
            }
        })
        .catch((err) => {
            console.log('ERROR invalid request', err);
        });
}

async function validateResponse() {
    console.log('validateResponse');

    let keyResolv2018 = new DID_SIOP.Resolvers.KeyDidResolver(
        'key',
        '@digitalbazaar/x25519-key-agreement-key-2018'
    );
    let siop_rp = await DID_SIOP.RP.getRP(
        'localhost:4200/home', // RP's redirect_uri
        'did:key:z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw', // RP's did
        {
            id_token_signed_response_alg: ['ES256K', 'ES256K-R', 'EdDSA', 'RS256']
        },
        undefined,
        [keyResolv2018]
    );

    console.log(siop_rp);

    siop_rp.addSigningParams(
        'zrv1xdp8ZsfXSDh4fQp8sE2VYPmLiCL3RssjKeXW7fYrRkxyWpWR5ugcC36WrCx9FizbJvxdwFmYcq7YxRVC2nVPFp5'
    );
    console.log('RP SigningParams added ...');
    let valid = await siop_rp.validateResponse(siopResponse);
    console.log('Response validated ...', valid);

    document.getElementById('validatedResponse').innerHTML = JSON.stringify(valid);
}
