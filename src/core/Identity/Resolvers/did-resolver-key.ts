import { DidResolver } from "./did-resolver-base";
import { DidDocument } from "../commons";
import { CRYPTO_SUITES } from "../../globals";

const {driver} = require('@digitalbazaar/did-method-key'); 
const {Ed25519VerificationKey2018} = require( '@digitalbazaar/ed25519-verification-key-2018');
const {Ed25519VerificationKey2020} = require( '@digitalbazaar/ed25519-verification-key-2020');

/**
 * @classdesc Resolver class for did:key
 * @extends {DidResolver}
 */
export class KeyDidResolver extends DidResolver{
    async resolveDidDocumet(did: string,crypto_suite?:string): Promise<DidDocument | undefined> {   
        if (crypto_suite === undefined) crypto_suite = CRYPTO_SUITES.Ed25519VerificationKey2020

        try{
            let didKeyDriver = this.getDidDriverForCryptoSuite(crypto_suite)     
            let didDocument:any = await didKeyDriver.get({did})
            
            return didDocument;
        }
        catch(err){
            console.log("KeyDidResolver Err",err);
            return undefined
        }
    }

    getDidDriverForCryptoSuite(crypto_suite_package:string):any{
        let didKeyDriver:any;

        switch (crypto_suite_package){
            case CRYPTO_SUITES.Ed25519VerificationKey2018 : 
                didKeyDriver = driver({verificationSuite: Ed25519VerificationKey2018});        
                break;
            default:
                didKeyDriver = driver({verificationSuite: Ed25519VerificationKey2020});        
                break;
        }
        return didKeyDriver;
    }    
}