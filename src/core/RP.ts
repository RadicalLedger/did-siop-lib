import { DidSiopResponse, CheckParams } from './Response';
import { RPInfo, DidSiopRequest } from './Request';
import { SigningInfo, JWTObject } from './JWT';
import { DidDocument, Identity } from './Identity';
import { KEY_FORMATS, ALGORITHMS, KTYS } from './globals';
import { KeyInputs, Key, RSAKey, ECKey, OKP } from './JWKUtils';
import { RSASigner, ES256KRecoverableSigner, ECSigner, OKPSigner } from './Signers';
import { RSAVerifier, ES256KRecoverableVerifier, ECVerifier, OKPVerifier } from './Verifiers';
import { checkKeyPair, isMultibasePvtKey ,getBase58fromMultibase} from './Utils';
import { SIOPErrorResponse } from './ErrorResponse';

export const ERRORS= Object.freeze({
    NO_SIGNING_INFO: 'At least one public key must be confirmed with related private key',
    NO_PUBLIC_KEY: 'No public key matches given private key',
});

/**
 * @classdesc This class provides the Relying Party functionality of DID based Self Issued OpenID Connect
 * @property {RPInfo} - Used to hold Relying Party information needed in issuing requests (ex:- redirect_uri)
 * @property {Identity} identity  - Used to store Decentralized Identity information of the Relying Party
 * @property {SigningInfo[]} signing_info_set - Used to store a list of cryptographic information used to sign DID SIOP requests
 */
export class RP {
    private info: RPInfo;
    private identity: Identity = new Identity();
    private signing_info_set: SigningInfo[] = [];

    /**
     * @private
     * @constructor 
     * @param {string} redirect_uri - Redirect uri of the RP. Response from the Provider is sent to this uri 
     * @param {string} did - Decentralized Identity of the Relying Party
     * @param {any} registration - Registration information of the Relying Party
     * https://openid.net/specs/openid-connect-core-1_0.html#RegistrationParameter
     * @param {DidDocument} [did_doc] - DID Document of the RP. Optional
     * @remarks - This is a private constructor used inside static async method getRP
     */
    private constructor(redirect_uri: string, did: string, registration: any, did_doc?: DidDocument) {
        this.info = {
            redirect_uri,
            did,
            registration,
            did_doc
        }
    }

    /**
     * @param {string} redirect_uri - Redirect uri of the RP. Response from the Provider is sent to this uri 
     * @param {string} did - Decentralized Identity of the Relying Party
     * @param {any} registration - Registration information of the Relying Party
     * https://openid.net/specs/openid-connect-core-1_0.html#RegistrationParameter
     * @param {DidDocument} [did_doc] - DID Document of the RP. Optional
     * @returns {Promise<RP>} - A Promise which resolves to an instance of RP class
     * @remarks Creating RP instances involves some async code and cannot be implemented as a constructor.
     * Hence this static method is used in place of the constructor.
     */
    static async getRP(redirect_uri: string, did: string, registration: any, did_doc?: DidDocument): Promise<RP> {
        try {
            let rp = new RP(redirect_uri, did, registration, did_doc)
            if(did_doc){
                rp.identity.setDocument(did_doc, did);
            }
            else{
                await rp.identity.resolve(did);
            }
            return rp;
        } catch (err) {
            return Promise.reject(err);
        }
    }

    /**
     * @param {string} key - Private part of any cryptographic key listed in the 'authentication' field of RP's DID Document
     * @param {string} [kid] - kid value of the key. Optional and not used
     * @param {KEY_FORMATS| string} [format] - Format in which the private key is supplied. Optional and not used
     * @param {ALGORITHMS} [algorithm] - Algorithm to use the key with. Optional and not used
     * @returns {string} - kid of the added key
     * @remarks This method is used to add signing information to 'signing_info_set'.
     * All optional parameters are not used and only there to make the library backward compatible.
     * Instead of using those optional parameters, given key is iteratively tried with 
     * every public key listed in the 'authentication' field of RP's DID Document and every key format
     * until a compatible combination of those information which can be used for the signing process is found. 
     */
    addSigningParams(key: string, kid?: string, format?: KEY_FORMATS | string, algorithm?: ALGORITHMS | string): string {
        try{
            if(format){}
            if(algorithm){}
            if(kid){}
            let didPublicKeySet = this.identity.extractAuthenticationKeys();
            
            if (isMultibasePvtKey(key))
                key = getBase58fromMultibase(key);
                
            for(let didPublicKey of didPublicKeySet){
                let publicKeyInfo: KeyInputs.KeyInfo = {
                    key: didPublicKey.publicKey,
                    kid: didPublicKey.id,
                    use: 'sig',
                    kty: KTYS[didPublicKey.kty],
                    alg: ALGORITHMS[didPublicKey.alg],
                    format: didPublicKey.format,
                    isPrivate: false
                }
   
                for(let key_format in KEY_FORMATS){                    
                    let privateKeyInfo: KeyInputs.KeyInfo = {
                        key: key,
                        kid: didPublicKey.id,
                        use: 'sig',
                        kty: KTYS[didPublicKey.kty],
                        alg: ALGORITHMS[didPublicKey.alg],
                        format: KEY_FORMATS[key_format as keyof typeof KEY_FORMATS],
                        isPrivate: true
                    }
        
                    let privateKey: Key;
                    let publicKey: Key | string;
                    let signer, verifier;
        
                   try{
                    switch(didPublicKey.kty){
                        case KTYS.RSA: {
                            privateKey = RSAKey.fromKey(privateKeyInfo);
                            publicKey = RSAKey.fromKey(publicKeyInfo);
                            signer = new RSASigner();
                            verifier = new RSAVerifier();
                            break;
                        };
                        case KTYS.EC: {
                            if(didPublicKey.format === KEY_FORMATS.ETHEREUM_ADDRESS){
                                privateKey = ECKey.fromKey(privateKeyInfo);
                                publicKey = didPublicKey.publicKey;
                                signer = new ES256KRecoverableSigner();
                                verifier = new ES256KRecoverableVerifier();
                            }
                            else{
                                privateKey = ECKey.fromKey(privateKeyInfo);
                                publicKey = ECKey.fromKey(publicKeyInfo);
                                signer = new ECSigner();
                                verifier = new ECVerifier();
                            }
                            break;
                        }
                        case KTYS.OKP: {
                            privateKey = OKP.fromKey(privateKeyInfo);
                            publicKey = OKP.fromKey(publicKeyInfo);
                            signer = new OKPSigner();
                            verifier = new OKPVerifier();
                            break;
                        };
                        default:{
                            continue;
                        }
                    }
        
                    if(checkKeyPair(privateKey, publicKey, signer, verifier, didPublicKey.alg)){
                        this.signing_info_set.push({
                            alg: didPublicKey.alg,
                            kid: didPublicKey.id,
                            key: key,
                            format: KEY_FORMATS[key_format as keyof typeof KEY_FORMATS],
                        })
                        return didPublicKey.id;
                    }
                   }
                   catch(err){
                       continue;
                   }
                }
            }
            throw new Error(ERRORS.NO_PUBLIC_KEY);
        }
        catch(err){
            throw err;
        }
    }

        /**
     * @param {string} pvtKey - private key provided by user for verifications
     * @param {KeyInputs.KeyInfo} pubKey - Public Key Info extracted from DID Document
     * @remarks TO BE FILLED
     */
         getKeyPairInfo(pvtKey: string, pubKey:KeyInputs.KeyInfo){
             if (pvtKey) {}
             if (pubKey) {}
        }
    

    /**
     * @param {string} kid - kid value of the SigningInfo which needs to be removed from the list
     * @remarks This method is used to remove a certain SigningInfo (key) which has the given kid value from the list. 
     */
    removeSigningParams(kid: string){
        try{
            this.signing_info_set = this.signing_info_set.filter(s => { return s.kid !== kid });
        }
        catch(err){
            throw err;
        }
    }

    /**
     * @param {any} [options = {}] - Any optional field which should be included in the request JWT. Any field which is not supported
     * at Provider's end will be ignored
     * @returns {Promise<string>} - A Promise which resolves to a DID SIOP request
     * @remarks This method is used to generate a request sent to a DID SIOP Provider.
     */
    async generateRequest(options:any = {}): Promise<string> {
        try{
            if(this.signing_info_set.length > 0){
                let signing_info = this.signing_info_set[Math.floor(Math.random() * this.signing_info_set.length)];
                return await DidSiopRequest.generateRequest(this.info, signing_info, options);
            }
            return Promise.reject(new Error(ERRORS.NO_SIGNING_INFO));
        }
        catch(err){
            return Promise.reject(err);
        }
    }

    /**
     * @param {string} request_uri - A uri from which a pre-configured and signed request JWT can be obtained
     * @param {any} [options = {}] - Any optional field which should be included in the request JWT. Any field which is not supported
     * at Provider's end will be ignored
     * @returns {Promise<string>} - A Promise which resolves to a DID SIOP request
     * @remarks This method is used to generate a request which has 'request_uri' in place of the 'request' parameter.
     * https://identity.foundation/did-siop/#generate-siop-request
     */
    async generateUriRequest(request_uri: string, options:any = {}): Promise<string> {
        try{
            this.info.request_uri = request_uri;
            return await this.generateRequest(options);
        }
        catch(err){
            return Promise.reject(ERRORS.NO_SIGNING_INFO);
        }
    }

    /**
     * @param {string} response - A DID SIOP response
     * @param {CheckParams} [checkParams = {redirect_uri: this.info.redirect_uri}] - Parameters against which the response needs to be validated
     * @returns {Promise<JWT.JWTObject> | SIOPErrorResponse} - A Promise which resolves either to a decoded response or a SIOPErrorResponse
     * @remarks This method is used to validate responses coming from DID SIOP Providers.
     */
    async validateResponse(response: string, checkParams: CheckParams = {redirect_uri: this.info.redirect_uri}): Promise<JWTObject | SIOPErrorResponse> {
        try {
            return await DidSiopResponse.validateResponse(response, checkParams);
        } catch (err) {
            return Promise.reject(err);
        }
    }
}
