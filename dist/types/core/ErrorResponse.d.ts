export interface SIOPErrorResponse {
    error: string;
    description: string;
    error_uri: string;
}
export interface SIOPError {
    err: Error;
    response: SIOPErrorResponse;
}
export declare const ERROR_RESPONSES: {
    invalid_request: SIOPError;
    unauthorized_client: SIOPError;
    access_denied: SIOPError;
    unsupported_response_type: SIOPError;
    invalid_scope: SIOPError;
    server_error: SIOPError;
    temporarily_unavailable: SIOPError;
    interaction_required: SIOPError;
    login_required: SIOPError;
    account_selection_required: SIOPError;
    consent_required: SIOPError;
    invalid_request_uri: SIOPError;
    invalid_request_object: SIOPError;
    request_not_supported: SIOPError;
    request_uri_not_supported: SIOPError;
    registration_not_supported: SIOPError;
};
/**
 * @param {string} errorMessage - The message of the SIOPErrorResponse which needs to be base64url encoded
 * @returns {string} - Base64url encoded SIOPErrorResponse
 * @remarks This method is used to get the base64url encoded version of a specific SIOPErrorResponse.
 */
export declare function getBase64URLEncodedError(errorMessage: string): string;
/**
 * @param {string} responseBase64Encoded - A base64url string which needs to be checked
 * @returns {SIOPErrorResponse | undefined} - SIOPErrorResponse or undefined
 * @remarks This method is used to check whether a given base64url encoded string is a SIOPErrorResponse.
 * If successful it will return the decoded SIOPErrorResponse or otherwise, undefined.
 */
export declare function checkErrorResponse(responseBase64Encoded: string): SIOPErrorResponse | undefined;
