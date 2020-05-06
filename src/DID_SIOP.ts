import { DidSiopResponse } from './Response';
import { SigningInfo, JWTObject } from './JWT';
import { Identity, DidDocument } from './Identity';
import { DidSiopRequest } from './Request';

const ERRORS= Object.freeze({
    NO_SIGNING_INFO: 'Atleast one SigningInfo is required',
    UNRESOLVED_IDENTITY: 'Unresolved identity',
});

export class SIOP{
    private identity: Identity = new Identity();
    private signing_info_set: SigningInfo[] = [];

    async setUser(did: string, doc?: DidDocument){
        try {
            if(doc){
                this.identity.setDocument(doc, did);
            }
            else{
                await this.identity.resolve(did);
            }
        } catch (err) {
            throw err;
        }
    }

    addSigningParams(signing_info: SigningInfo) {
        this.signing_info_set.push(signing_info);
    }

    async validateRequest(request: string): Promise<JWTObject>{
        try {
            return DidSiopRequest.validateRequest(request);
        } catch (err) {
            throw err;
        }
    }

    async generateResponse(requestPayload: any, expiresIn: number = 1000): Promise<string>{
        try{
            if(this.signing_info_set.length > 0){
                let signing_info = this.signing_info_set[Math.floor(Math.random() * this.signing_info_set.length)];

                if(this.identity.isResolved()){
                    return await DidSiopResponse.generateResponse(requestPayload, signing_info, this.identity, expiresIn);
                }
                else{
                    throw new Error(ERRORS.UNRESOLVED_IDENTITY);
                }
            }
            throw new Error(ERRORS.NO_SIGNING_INFO);
        }
        catch(err){
            throw err;
        }
    }
}