/// <reference types="node" />
import { Key, RSAKey, ECKey, OKP } from './JWKUtils';
import { ALGORITHMS } from './globals';
export declare const ERRORS: Readonly<{
    NO_PRIVATE_KEY: string;
    INVALID_ALGORITHM: string;
}>;
/**
 * @classdesc This abstract class defines the interface for classes used to cryptographically sign messages
 */
export declare abstract class Signer {
    /**
     * @param {string} message - Message which needs to be signed
     * @param {Key} key - A Key object used to sign the message
     * @param {ALGORITHMS} [algorithm] - The algorithm used for the signing process.
     * This param is defined as optional here because some Signers only support a specific algorithm
     * @returns {Buffer} - A Buffer object which contains the generated signature in binary form
     * @remarks This is the method which will essentially be used for signing process.
     * Any extending subclass must provide a concrete definition for this method.
     */
    abstract sign(message: string, key: Key | string, algorithm?: ALGORITHMS): Buffer;
}
/**
 * @classdesc This class provides RSA message signing
 * @extends {Signer}
 */
export declare class RSASigner extends Signer {
    /**
     * @param {string} message - Message which needs to be signed
     * @param {RSAKey} key - An RSAKey object used to sign the message
     * @param {ALGORITHMS} algorithm - The algorithm used for the signing process. Must be one of RSA + SHA variant
     * @returns {Buffer} - A Buffer object which contains the generated signature in binary form
     * @remarks This method first checks if the key provided has private part. Then it proceed to sign the message using
     * selected algorithm (RSA + given SHA variant)
     */
    sign(message: string, key: RSAKey, algorithm: ALGORITHMS): Buffer;
}
/**
 * @classdesc This class provides Elliptic Curve message signing
 * @extends {Signer}
 */
export declare class ECSigner extends Signer {
    /**
     * @param {string} message - Message which needs to be signed
     * @param {ECKey} key - An ECKey object used to sign the message
     * @param {ALGORITHMS} algorithm - The algorithm used for the signing process. Must be one of Curve variant + SHA variant
     * @returns {Buffer} - A Buffer object which contains the generated signature in binary form
     * @remarks This method first checks if the key provided has private part. Then it proceed to sign the message using
     * selected algorithm (given Curve + given SHA variant)
     */
    sign(message: string, key: ECKey, algorithm: ALGORITHMS): Buffer;
}
/**
 * @classdesc This class provides Edwards Curve message signing
 * @extends {Signer}
 */
export declare class OKPSigner extends Signer {
    /**
     * @param {string} message - Message which needs to be signed
     * @param {OKP} key - An OKP object used to sign the message
     * @param {ALGORITHMS} algorithm - The algorithm used for the signing process. (ed25519 curve)
     * @returns {Buffer} - A Buffer object which contains the generated signature in binary form
     * @remarks This method first checks if the key provided has private part. Then it proceed to sign the message using
     * selected algorithm (ed25519)
     */
    sign(message: string, key: OKP, algorithm: ALGORITHMS): Buffer;
}
/**
 * @classdesc This class provides message signing using ES256K-R algorithm
 * @extends {Signer}
 */
export declare class ES256KRecoverableSigner extends Signer {
    /**
     * @param {string} message - Message which needs to be signed
     * @param {ECKey | string} key - The key either as an ECKey or a hex string
     * @returns {Buffer} - A Buffer object which contains the generated signature in binary form
     * @remarks This method first checks whether the key is a string. If it is not then it will be converted to string
     * using ECKey.exportKey(). This class supports only one algorithm which is curve secp256k1 recoverable method.
     */
    sign(message: string, key: ECKey | string): Buffer;
}
