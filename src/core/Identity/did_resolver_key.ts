import { DidResolver } from "./did_resolver_base";
import { DidDocument } from "./commons";

const {Ed25519VerificationKey2018} = require( '@digitalbazaar/ed25519-verification-key-2018');
const didKeyDriver = require('@digitalbazaar/did-method-key').driver({verificationSuite: Ed25519VerificationKey2018});


/**
 * @classdesc Resolver class for did:key
 * @extends {DidResolver}
 */
 export class KeyDidResolver2 extends DidResolver{
    async resolveDidDocumet(did: string): Promise<DidDocument | undefined> {        
        try{
            let didDocument:any = await didKeyDriver.get({did})
            return didDocument;
        }
        catch(err){
            return undefined
        }
    }
}