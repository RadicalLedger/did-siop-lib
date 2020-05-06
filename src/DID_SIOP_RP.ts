import { DidSiopResponse, CheckParams } from './Response';
import { RPInfo, DidSiopRequest } from './Request';
import { SigningInfo } from './JWT';
import { DidDocument } from './Identity';

const ERRORS= Object.freeze({
    NO_SIGNING_INFO: 'Atleast one SigningInfo is required',
});

export class RP {
    private info: RPInfo;
    private signing_info_set: SigningInfo[] = [];

    constructor(redirect_uri: string, did: string, registration: any, did_doc?: DidDocument) {
        this.info = {
            redirect_uri,
            did,
            registration,
            did_doc
        }
    }

    addSigningParams(signing_info: SigningInfo) {
        this.signing_info_set.push(signing_info);
    }

    async generateRequest(options:any = {}): Promise<string> {
        try{
            if(this.signing_info_set.length > 0){
                let signing_info = this.signing_info_set[Math.floor(Math.random() * this.signing_info_set.length)];
                return await DidSiopRequest.generateRequest(this.info, signing_info, options);
            }
            throw new Error(ERRORS.NO_SIGNING_INFO);
        }
        catch(err){
            throw err;
        }
    }

    async generateUriRequest(request_uri: string, options:any = {}): Promise<string> {
        try{
            this.info.request_uri = request_uri;
            return await this.generateRequest(options);
        }
        catch(err){
            throw err;
        }
    }

    async validateResponse(response: string, checkParams: CheckParams = {redirect_uri: this.info.redirect_uri}): Promise<any> {
        try {
            return await DidSiopResponse.validateResponse(response, checkParams);
        } catch (err) {
            throw err;
        }
    }
}
