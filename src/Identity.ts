import { RESOLVER_URL } from './config';
const axios = require('axios').default;

interface DidDocument{
    '@context': string,
    id: string,
    authentication: any[],
    [propName:string]: any,
}

export const ERRORS = Object.freeze(
    {
        DOCUMENT_RESOLUTION_ERROR: new Error('Cannot resolve document for did'),
        INVALID_DID_ERROR: new Error('Invalid did'),
    }
);

export class Identity{
    private doc: DidDocument;

    constructor(){
        this.doc = {
            '@context': '',
            id: '',
            authentication: [],
        };
    }

    async resolve(did: string){
        try{
            let result = await axios.get(RESOLVER_URL + did);
            if(
                result &&
                result.data &&
                result.data.didDocument &&
                result.data.didDocument['@context'] === 'https://w3id.org/did/v1' &&
                result.data.didDocument.id == did &&
                result.data.didDocument.authentication &&
                result.data.didDocument.authentication.length > 0
            ){
                this.doc = result.data.didDocument;
                return this.doc.id;
            }
            throw ERRORS.INVALID_DID_ERROR;
        }
        catch(err){
            throw ERRORS.DOCUMENT_RESOLUTION_ERROR;
        }
    }

    isResolved(){
        return this.doc.id !== '';
    }
}