/// <reference types="node" />
import { Key, RSAKey, ECKey, OKP } from "./JWKUtils";
import { ALGORITHMS } from "./globals";
export declare const ERRORS: Readonly<{
    NO_PRIVATE_KEY: string;
    INVALID_ALGORITHM: string;
    INVALID_SIGNATURE: string;
}>;
/**
 * @classdesc This abstract class defines the interface for classes used to verify cryptographically signed messages
 */
export declare abstract class Verifier {
    /**
     * @param {string} msg - The message which needs to be verified
     * @param {Buffer} signature - The signature of the message
     * @param {Key} key - Key object used for verification (Public Key)
     * @param {ALGORITHMS} [algorithm] - The algorithm used. This param is defined as optional here because
     * some Verifiers only support a specific algorithm
     * @returns {boolean} - The result of the verification. Indicates whether the given signature matches the message.
     * @remarks This is the method which will essentially be used for verification process.
     * Any extending subclass must provide a concrete definition for this method.
     */
    abstract verify(msg: string, signature: Buffer, key: Key | string, algorithm?: ALGORITHMS): boolean;
}
/**
 * @classdesc This class provides RSA signature verification
 * @extends {Verifier}
 */
export declare class RSAVerifier extends Verifier {
    /**
     * @param {string} msg - The message which needs to be verified
     * @param {Buffer} signature - The signature of the message
     * @param {RSAKey} key - An RSAKey object used for verification (Public Key)
     * @param {ALGORITHMS} algorithm - The algorithm used for the verification process. Must be one of RSA + SHA variant
     * @returns {boolean} - The result of the verification. Indicates whether the given signature matches the message.
     * @remarks This method will verify the message using selected algorithm and return the result.
     */
    verify(msg: string, signature: Buffer, key: RSAKey, algorithm?: ALGORITHMS | undefined): boolean;
}
/**
 * @classdesc This class provides Elliptic Curve signature verification
 * @extends {Verifier}
 */
export declare class ECVerifier extends Verifier {
    /**
     * @param {string} msg - The message which needs to be verified
     * @param {Buffer} signature - The signature of the message
     * @param {ECKey} key - An ECKey object used for verification (Public Key)
     * @param {ALGORITHMS} algorithm - The algorithm used for the verification process. Must be one of Curve variant + SHA variant
     * @returns {boolean} - The result of the verification. Indicates whether the given signature matches the message.
     * @remarks This method will verify the message using selected algorithm and return the result.
     */
    verify(msg: string, signature: Buffer, key: ECKey, algorithm?: ALGORITHMS | undefined): boolean;
}
/**
 * @classdesc This class provides Edwards Curve signature verification
 * @extends {Verifier}
 */
export declare class OKPVerifier extends Verifier {
    /**
     * @param {string} msg - The message which needs to be verified
     * @param {Buffer} signature - The signature of the message
     * @param {OKP} key - An OKP object used for verification (Public Key)
     * @param {ALGORITHMS} algorithm - The algorithm used for the verification process. (ed25519)
     * @returns {boolean} - The result of the verification. Indicates whether the given signature matches the message.
     * @remarks This method will verify the message using selected algorithm (ed25519) and return the result.
     */
    verify(msg: string, signature: Buffer, key: OKP, algorithm?: ALGORITHMS | undefined): boolean;
}
/**
 * @classdesc This class provides signature verification using ES256K-R algorithm
 * @extends {Verifier}
 */
export declare class ES256KRecoverableVerifier extends Verifier {
    /**
     * @param {string} msg - The message which needs to be verified
     * @param {Buffer} signature - The signature of the message
     * @param {ECKey | string} key - Public Key either as an ECKey or a hex string
     * @returns {boolean} - The result of the verification. Indicates whether the given signature matches the message.
     * @remarks This method first checks whether the key is a string. If it is not then it will be converted to string
     * using ECKey.exportKey(). This class supports only one algorithm which is curve secp256k1 recoverable method.
     */
    verify(msg: string, signature: Buffer, key: ECKey | string): boolean;
}
