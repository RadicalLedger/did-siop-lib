"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var base64url_1 = __importDefault(require("base64url"));
//OAuth 2.0
var invalid_request = {
    err: new Error('invalid_request'),
    response: {
        error: 'invalid_request',
        description: 'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.',
        error_uri: ''
    }
};
var unauthorized_client = {
    err: new Error('unauthorized_client'),
    response: {
        error: 'unauthorized_client',
        description: 'The client is not authorized to request an authorization code using this method.',
        error_uri: ''
    }
};
var access_denied = {
    err: new Error('access_denied'),
    response: {
        error: 'access_denied',
        description: 'The resource owner or authorization server denied the request.',
        error_uri: ''
    }
};
var unsupported_response_type = {
    err: new Error('unsupported_response_type'),
    response: {
        error: 'unsupported_response_type',
        description: 'The authorization server does not support obtaining an authorization code using this method.',
        error_uri: ''
    }
};
var invalid_scope = {
    err: new Error('invalid_scope'),
    response: {
        error: 'invalid_scope',
        description: 'The requested scope is invalid, unknown, or malformed.',
        error_uri: ''
    }
};
var server_error = {
    err: new Error('server_error'),
    response: {
        error: 'server_error',
        description: 'The authorization server encountered an unexpected condition that prevented it from fulfilling the request',
        error_uri: ''
    }
};
var temporarily_unavailable = {
    err: new Error('temporarily_unavailable'),
    response: {
        error: 'temporarily_unavailable',
        description: 'The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.',
        error_uri: ''
    }
};
//OpenId Connect
var interaction_required = {
    err: new Error('interaction_required'),
    response: {
        error: 'interaction_required',
        description: 'The Authorization Server requires End-User interaction of some form to proceed.',
        error_uri: ''
    }
};
var login_required = {
    err: new Error('login_required'),
    response: {
        error: 'login_required',
        description: 'The Authorization Server requires End-User authentication.',
        error_uri: ''
    }
};
var account_selection_required = {
    err: new Error('account_selection_required'),
    response: {
        error: 'account_selection_required',
        description: 'The End-User is REQUIRED to select a session at the Authorization Server.',
        error_uri: ''
    }
};
var consent_required = {
    err: new Error('consent_required'),
    response: {
        error: 'consent_required',
        description: 'The Authorization Server requires End-User consent.',
        error_uri: ''
    }
};
var invalid_request_uri = {
    err: new Error('invalid_request_uri'),
    response: {
        error: 'invalid_request_uri',
        description: 'The request_uri in the Authorization Request returns an error or contains invalid data.',
        error_uri: ''
    }
};
var invalid_request_object = {
    err: new Error('invalid_request_object'),
    response: {
        error: 'invalid_request_object',
        description: 'The request parameter contains an invalid Request Object.',
        error_uri: ''
    }
};
var request_not_supported = {
    err: new Error('request_not_supported'),
    response: {
        error: 'request_not_supported',
        description: 'The OP does not support use of the request parameter.',
        error_uri: ''
    }
};
var request_uri_not_supported = {
    err: new Error('request_uri_not_supported'),
    response: {
        error: 'request_uri_not_supported',
        description: 'The OP does not support use of the request_uri parameter',
        error_uri: ''
    }
};
var registration_not_supported = {
    err: new Error('registration_not_supported'),
    response: {
        error: 'registration_not_supported',
        description: 'The OP does not support use of the registration parameter',
        error_uri: ''
    }
};
exports.ERROR_RESPONSES = {
    invalid_request: invalid_request,
    unauthorized_client: unauthorized_client,
    access_denied: access_denied,
    unsupported_response_type: unsupported_response_type,
    invalid_scope: invalid_scope,
    server_error: server_error,
    temporarily_unavailable: temporarily_unavailable,
    interaction_required: interaction_required,
    login_required: login_required,
    account_selection_required: account_selection_required,
    consent_required: consent_required,
    invalid_request_uri: invalid_request_uri,
    invalid_request_object: invalid_request_object,
    request_not_supported: request_not_supported,
    request_uri_not_supported: request_uri_not_supported,
    registration_not_supported: registration_not_supported,
};
/**
 * @param {string} errorMessage - The message of the SIOPErrorResponse which needs to be base64url encoded
 * @returns {string} - Base64url encoded SIOPErrorResponse
 * @remarks This method is used to get the base64url encoded version of a specific SIOPErrorResponse.
 */
function getBase64URLEncodedError(errorMessage) {
    var error = exports.ERROR_RESPONSES[errorMessage];
    if (error) {
        return base64url_1.default.encode(JSON.stringify(error.response));
    }
    else {
        return base64url_1.default.encode(JSON.stringify({
            error: 'unknown_error',
            description: 'Unknown error occured.',
            error_uri: ''
        }));
    }
}
exports.getBase64URLEncodedError = getBase64URLEncodedError;
/**
 * @param {string} responseBase64Encoded - A base64url string which needs to be checked
 * @returns {SIOPErrorResponse | undefined} - SIOPErrorResponse or undefined
 * @remarks This method is used to check whether a given base64url encoded string is a SIOPErrorResponse.
 * If successful it will return the decoded SIOPErrorResponse or otherwise, undefined.
 */
function checkErrorResponse(responseBase64Encoded) {
    try {
        var errorResponseDecoded = JSON.parse(base64url_1.default.decode(responseBase64Encoded));
        if (errorResponseDecoded.error &&
            errorResponseDecoded.description !== undefined &&
            errorResponseDecoded.description !== null &&
            errorResponseDecoded.error_uri !== undefined &&
            errorResponseDecoded.error_uri !== null) {
            return errorResponseDecoded;
        }
        return undefined;
    }
    catch (err) {
        return undefined;
    }
}
exports.checkErrorResponse = checkErrorResponse;
//# sourceMappingURL=ErrorResponse.js.map