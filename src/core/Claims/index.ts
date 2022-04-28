
import { ERROR_RESPONSES } from '../ErrorResponse';
import { validJsonObject} from '../Utils';

/** @param {any} decodedPayload - Decoded payload of the JWT
 * @returns {boolean>} - true if all optional parameters are valid, false otherwise
 * @remarks This method is used to validate optional elements of the Authentication Request. 
 * Currently valuidates claims/vp_token property if exist
 * https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0.html#name-vp_token
 */
export async function validateRequestJWTClaims(decodedPayload: any): Promise<any> {
    if (decodedPayload.claims) {
        if (!validJsonObject(decodedPayload.claims))
            return Promise.reject(ERROR_RESPONSES.invalid_claim.err)
        if (decodedPayload.claims.vp_token) {
            if (!validJsonObject(decodedPayload.claims.vp_token))
                return Promise.reject(ERROR_RESPONSES.invalid_vp_token.err)
            if (decodedPayload.claims.vp_token.presentation_definition) {
                if (!validJsonObject(decodedPayload.claims.vp_token.presentation_definition))
                    return Promise.reject(ERROR_RESPONSES.invalid_vp_token.err)
            }
            else{
                return Promise.reject(ERROR_RESPONSES.vp_token_missing_presentation_definition.err) // if vp_token exists,the presentation_definition must exist
            }    
        }
    }
    return Promise.resolve()
}