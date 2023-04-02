import base64url from 'base64url';

export interface SIOPErrorResponse {
    error: string;
    description: string;
    error_uri: string;
}

export interface SIOPError {
    err: Error;
    response: SIOPErrorResponse;
}

//OAuth 2.0
const invalid_request: SIOPError = {
    err: new Error('invalid_request'),
    response: {
        error: 'invalid_request',
        description:
            'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.',
        error_uri: ''
    }
};

const unauthorized_client: SIOPError = {
    err: new Error('unauthorized_client'),
    response: {
        error: 'unauthorized_client',
        description:
            'The client is not authorized to request an authorization code using this method.',
        error_uri: ''
    }
};

const access_denied: SIOPError = {
    err: new Error('access_denied'),
    response: {
        error: 'access_denied',
        description: 'The resource owner or authorization server denied the request.',
        error_uri: ''
    }
};

const unsupported_response_type: SIOPError = {
    err: new Error('unsupported_response_type'),
    response: {
        error: 'unsupported_response_type',
        description:
            'The authorization server does not support obtaining an authorization code using this method.',
        error_uri: ''
    }
};

const invalid_scope: SIOPError = {
    err: new Error('invalid_scope'),
    response: {
        error: 'invalid_scope',
        description: 'The requested scope is invalid, unknown, or malformed.',
        error_uri: ''
    }
};

const server_error: SIOPError = {
    err: new Error('server_error'),
    response: {
        error: 'server_error',
        description:
            'The authorization server encountered an unexpected condition that prevented it from fulfilling the request',
        error_uri: ''
    }
};

const temporarily_unavailable: SIOPError = {
    err: new Error('temporarily_unavailable'),
    response: {
        error: 'temporarily_unavailable',
        description:
            'The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.',
        error_uri: ''
    }
};

//OpenId Connect
const interaction_required: SIOPError = {
    err: new Error('interaction_required'),
    response: {
        error: 'interaction_required',
        description:
            'The Authorization Server requires End-User interaction of some form to proceed.',
        error_uri: ''
    }
};

const login_required: SIOPError = {
    err: new Error('login_required'),
    response: {
        error: 'login_required',
        description: 'The Authorization Server requires End-User authentication.',
        error_uri: ''
    }
};

const account_selection_required: SIOPError = {
    err: new Error('account_selection_required'),
    response: {
        error: 'account_selection_required',
        description: 'The End-User is REQUIRED to select a session at the Authorization Server.',
        error_uri: ''
    }
};

const consent_required: SIOPError = {
    err: new Error('consent_required'),
    response: {
        error: 'consent_required',
        description: 'The Authorization Server requires End-User consent.',
        error_uri: ''
    }
};

const invalid_request_uri: SIOPError = {
    err: new Error('invalid_request_uri'),
    response: {
        error: 'invalid_request_uri',
        description:
            'The request_uri in the Authorization Request returns an error or contains invalid data.',
        error_uri: ''
    }
};

const invalid_request_object: SIOPError = {
    err: new Error('invalid_request_object'),
    response: {
        error: 'invalid_request_object',
        description: 'The request parameter contains an invalid Request Object.',
        error_uri: ''
    }
};

const request_not_supported: SIOPError = {
    err: new Error('request_not_supported'),
    response: {
        error: 'request_not_supported',
        description: 'The OP does not support use of the request parameter.',
        error_uri: ''
    }
};

const request_uri_not_supported: SIOPError = {
    err: new Error('request_uri_not_supported'),
    response: {
        error: 'request_uri_not_supported',
        description: 'The OP does not support use of the request_uri parameter',
        error_uri: ''
    }
};

const registration_not_supported: SIOPError = {
    err: new Error('registration_not_supported'),
    response: {
        error: 'registration_not_supported',
        description: 'The OP does not support use of the registration parameter',
        error_uri: ''
    }
};

const invalid_claim: SIOPError = {
    err: new Error('invalid_claim'),
    response: {
        error: 'invalid_claim',
        description: 'Value of claim is not a valid JSON',
        error_uri: ''
    }
};
const invalid_vp_token: SIOPError = {
    err: new Error('invalid_vp_token'),
    response: {
        error: 'invalid_vp_token',
        description: 'Value of vp_token is not a valid JSON',
        error_uri: ''
    }
};

const invalid_presentation_definition: SIOPError = {
    err: new Error('invalid_presentation_definition'),
    response: {
        error: 'invalid_presentation_definition',
        description: 'Value of presentation_definition is not a valid JSON',
        error_uri: ''
    }
};

const vp_token_missing_presentation_definition: SIOPError = {
    err: new Error('vp_token_missing_presentation_definition'),
    response: {
        error: 'vp_token_missing_presentation_definition',
        description: 'Property presentation_definition is missing in vp_token',
        error_uri: ''
    }
};
const vp_token_missing_verifiableCredential: SIOPError = {
    err: new Error('vp_token_missing_verifiableCredential'),
    response: {
        error: 'vp_token_missing_verifiableCredential',
        description: 'Property verifiableCredential is missing in vp_token',
        error_uri: ''
    }
};

export const ERROR_RESPONSES = {
    invalid_request,
    unauthorized_client,
    access_denied,
    unsupported_response_type,
    invalid_scope,
    server_error,
    temporarily_unavailable,
    interaction_required,
    login_required,
    account_selection_required,
    consent_required,
    invalid_request_uri,
    invalid_request_object,
    request_not_supported,
    request_uri_not_supported,
    registration_not_supported,
    invalid_claim,
    invalid_vp_token,
    invalid_presentation_definition,
    vp_token_missing_presentation_definition,
    vp_token_missing_verifiableCredential
};

/**
 * @param {string} errorMessage - The message of the SIOPErrorResponse which needs to be base64url encoded
 * @returns {string} - Base64url encoded SIOPErrorResponse
 * @remarks This method is used to get the base64url encoded version of a specific SIOPErrorResponse.
 */
export function getBase64URLEncodedError(errorMessage: string): string {
    let error = ERROR_RESPONSES[errorMessage as keyof typeof ERROR_RESPONSES];
    if (error) {
        return base64url.encode(JSON.stringify(error.response));
    } else {
        return base64url.encode(
            JSON.stringify({
                error: 'unknown_error',
                description: 'Unknown error occured.',
                error_uri: ''
            })
        );
    }
}

/**
 * @param {string} responseBase64Encoded - A base64url string which needs to be checked
 * @returns {SIOPErrorResponse | undefined} - SIOPErrorResponse or undefined
 * @remarks This method is used to check whether a given base64url encoded string is a SIOPErrorResponse.
 * If successful it will return the decoded SIOPErrorResponse or otherwise, undefined.
 */
export function checkErrorResponse(responseBase64Encoded: string): SIOPErrorResponse | undefined {
    try {
        let errorResponseDecoded = JSON.parse(base64url.decode(responseBase64Encoded));
        if (
            errorResponseDecoded.error &&
            errorResponseDecoded.description !== undefined &&
            errorResponseDecoded.description !== null &&
            errorResponseDecoded.error_uri !== undefined &&
            errorResponseDecoded.error_uri !== null
        ) {
            return errorResponseDecoded;
        }
        return undefined;
    } catch (err) {
        return undefined;
    }
}
