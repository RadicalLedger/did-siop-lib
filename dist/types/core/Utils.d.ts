import { Key } from "./JWKUtils";
import { ALGORITHMS, KEY_FORMATS, KTYS } from "./globals";
import { Signer } from "./Signers";
import { Verifier } from "./Verifiers";
/**
 * @param {string} data - The string value needed to be padded
 * @param {number} [size = 64] - Required size (with padding). Default value is 64
 * @returns {string} - Left '0' padded string with the length specified by size param
 * @remarks This is a helper method used to add '0's to the start of a string
 * in order to increase its length to a specific value
 */
export declare function leftpad(data: any, size?: number): any;
/**
 * @param {Key} privateKey - A Key object consisting of the private part of an asymmetric key pair
 * @param {Key} publicKey - A Key object consisting of the public part of an asymmetric key pair
 * @param {Signer} signer - A Signer object to test with the key pair
 * @param {Verifier} verifier - An object of related Verifier
 * @param {ALGORITHMS} algorithm - The algorithm to test with
 * @returns {boolean} - A boolean value indicating the validity of two Keys.
 * @remarks This is a helper function used to check if a certain private key relates to a certain public key
 */
export declare function checkKeyPair(privateKey: Key | string, publicKey: Key | string, signer: Signer, verifier: Verifier, algorithm: ALGORITHMS): boolean;
/**
 * @param {string} alg - Name of the algorithm as a string
 * @returns {ALGORITHMS} - Related enum type of the algorihm
 * @remarks This function is used to convert an algorithm name given as a string to a ALGORITHM value
 */
export declare function getAlgorithm(alg: string): ALGORITHMS;
/**
 * @param {string} format - Name of the key format as a string
 * @returns {KEY_FORMATS} - Related enum type of the key format
 * @remarks This function is used to convert a key format given as a string to a KEY_FORMAT value
 */
export declare function getKeyFormat(format: string): KEY_FORMATS;
/**
 * @param {string} kty - Name of the key type as a string
 * @returns {KTYS} - Related enum type of the key type
 * @remarks This function is used to convert a key type name given as a string to a KTYS value
 */
export declare function getKeyType(kty: string): KTYS;
