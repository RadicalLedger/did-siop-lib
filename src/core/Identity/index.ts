import { DidDocument, DidVerificationKey, ERRORS } from './commons';
import { DidVerificationKeyExtractor, uniExtractor } from './key-extractors';
import { combinedDidResolver } from './resolvers';

export class Identity{
    private doc: DidDocument;
    private keySet: DidVerificationKey[];

    constructor(){
        this.doc = {
            '@context': '',
            id: '',
            authentication: [],
        };
        this.keySet = [];
    }

    async resolve(did: string): Promise<string>{
        let result: DidDocument;
        try{
            result = await combinedDidResolver.resolve(did);
        }
        catch(err){
            throw new Error(ERRORS.DOCUMENT_RESOLUTION_ERROR);
        }

        if(
            result &&
            //result.data.didDocument['@context'] === 'https://w3id.org/did/v1' &&
            result.id == did &&
            result.authentication &&
            result.authentication.length > 0
        ){
            this.doc = result;
            this.keySet = [];
            return this.doc.id;
        }
        throw new Error(ERRORS.INVALID_DID_ERROR);
    }

    isResolved(){
        return this.doc.id !== '';
    }

    extractAuthenticationKeys(extractor?: DidVerificationKeyExtractor): DidVerificationKey[]{
        if(!extractor) extractor = uniExtractor;
        if(!this.isResolved()) throw new Error(ERRORS.UNRESOLVED_DOCUMENT);
        if(this.keySet.length === 0){
            for (let method of this.doc.authentication) {
                if (method.id && method.type) {
                    try{
                        this.keySet.push(extractor.extract(method));
                    }
                    catch(err){
                        continue;
                    }
                }
    
                if (method.publicKey) {
                    for (let key of method.publicKey) {
                        for(let pub of this.doc.publicKey){
                            if (pub.id === key || pub.id === this.doc.id + key){
                                try{
                                    this.keySet.push(extractor.extract(pub));
                                }
                                catch(err){
                                    continue;
                                }
                            }
                        }
                    }
                }
    
                if (typeof method === 'string') {
                    for (let pub of this.doc.publicKey) {
                        if (pub.id === method){
                            try{
                                this.keySet.push(extractor.extract(pub));
                            }
                            catch(err){
                                continue;
                            }
                        }
                    }
                    //Implement other verification methods here
                }
            }
        }
        return this.keySet;
    }

    getDocument(): DidDocument{
        return this.doc;
    }

    setDocument(doc: DidDocument, did: string){
        if (
            //doc['@context'] === 'https://w3id.org/did/v1' &&
            doc.id == did &&
            doc.authentication &&
            doc.authentication.length > 0
        ) {
            this.doc = doc;
        }
        else {
            throw new Error(ERRORS.INVALID_DOCUMENT);
        }
    }
}

export { DidDocument, DidVerificationKey, DidVerificationKeyMethod, ERRORS } from './commons';
export { DidVerificationKeyExtractor, uniExtractor} from './key-extractors';
