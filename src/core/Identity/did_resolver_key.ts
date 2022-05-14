import { DidResolver } from "./did_resolver_base";
import { DidDocument } from "./commons";
import { CRYPTO_SUITES } from "../globals";

// const {Ed25519VerificationKey2018} = require( '@digitalbazaar/ed25519-verification-key-2018');
// const didKeyDriver = require('@digitalbazaar/did-method-key').driver({verificationSuite: Ed25519VerificationKey2018});


/**
 * @classdesc Resolver class for did:key
 * @extends {DidResolver}
 */
export class KeyDidResolver2 extends DidResolver{
    async resolveDidDocumet(did: string,crypto_suite?:string): Promise<DidDocument | undefined> {   

        if (crypto_suite === undefined) crypto_suite = CRYPTO_SUITES.Ed25519VerificationKey2020

        let didKeyDriver = this.getDidDriverForCryptoSuite(crypto_suite)     
        try{
            let didDocument:any = await didKeyDriver.get({did})
            return didDocument;
        }
        catch(err){
            return undefined
        }
    }

    getDidDriverForCryptoSuite(crypto_suite_package:string):any{
        let didKeyDriver:any;
    
        switch (crypto_suite_package){
            case CRYPTO_SUITES.Ed25519VerificationKey2018 : 
                const {Ed25519VerificationKey2018} = require( CRYPTO_SUITES.Ed25519VerificationKey2018 );        
                didKeyDriver = require('@digitalbazaar/did-method-key').driver({verificationSuite: Ed25519VerificationKey2018});        
                break;
            default:
                const {Ed25519VerificationKey2020} = require( CRYPTO_SUITES.Ed25519VerificationKey2020 );        
                didKeyDriver = require('@digitalbazaar/did-method-key').driver({verificationSuite: Ed25519VerificationKey2020});        
                break;
        }
        return didKeyDriver;
    }    
}