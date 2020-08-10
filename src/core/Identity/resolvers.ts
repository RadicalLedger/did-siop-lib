import { DidDocument } from "./commons";
import { ERRORS } from "./commons";
import { getResolver } from 'ethr-did-resolver';
const axios = require('axios').default;

abstract class DidResolver{
    abstract async resolve(did: string): Promise<DidDocument>;
}

class CombinedDidResolver extends DidResolver{
    private resolvers: any[] = [];

    addResolver(resolver: any): CombinedDidResolver{
        this.resolvers.push(resolver);
        return this;
    }

    async resolve(did: string): Promise<DidDocument>{
        let doc: DidDocument | undefined;

        for(let resolver of this.resolvers){
            try{
                doc = await resolver.resolve(did);
                if(!doc){
                    continue;
                }
                else{
                    return doc;
                }
            }
            catch(err){
                continue;
            }
        }
        throw new Error(ERRORS.DOCUMENT_RESOLUTION_ERROR);
    }
}

class EthrDidResolver extends DidResolver{
    async resolve(did: string): Promise<DidDocument> {
        const providerConfig = { rpcUrl: 'https://ropsten.infura.io/v3/e0a6ac9a2c4a4722970325c36b728415'};
        let resolve = getResolver(providerConfig).ethr;
        return await resolve(did, {
            did,
            method: 'ethr',
            id: did.split(':')[2],
            didUrl: did
        });
    }
}

class UniversalDidResolver extends DidResolver{
    async resolve(did: string): Promise<DidDocument>{
        let returned = await axios.get('https://dev.uniresolver.io/1.0/identifiers/' + did);
        return returned.data.didDocument;
    }
}



export const combinedDidResolver = new CombinedDidResolver()
    .addResolver(new EthrDidResolver())
    .addResolver(new UniversalDidResolver());
