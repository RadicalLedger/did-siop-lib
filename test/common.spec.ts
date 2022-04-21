import { JWTObject, SigningInfo } from '../src/core/JWT';
import { sign } from '../src/core/JWT';

export const getModifiedJWT = function (jwt: JWTObject, privateKey: SigningInfo, isPayload: boolean, property: string, value?: any) {    
    let newJWT = JSON.parse(JSON.stringify(jwt));
    if (isPayload) {
        if (value === null) {
            delete newJWT.payload[property];
        }
        else {
            newJWT.payload[property] = value;
        }
    }
    else {
        if (!value) {
            delete newJWT.header[property];
        } else {
            newJWT.header[property] = value;
        }
    }
    return sign(newJWT, privateKey);
}