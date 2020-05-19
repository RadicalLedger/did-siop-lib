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
export declare function getBase64URLEncodedError(errorMessage: string): string;
export declare function checkErrorResponse(responseBase64Encoded: string): SIOPErrorResponse | undefined;
