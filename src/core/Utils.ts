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
export function leftpad(data: any, size: number = 64) {
    if (data.length === size) return data
    return '0'.repeat(size - data.length) + data
}

/**
 * @param {Key} privateKey - A Key object consisting of the private part of an asymmetric key pair
 * @param {Key} publicKey - A Key object consisting of the public part of an asymmetric key pair
 * @param {Signer} signer - A Signer object to test with the key pair
 * @param {Verifier} verifier - An object of related Verifier
 * @param {ALGORITHMS} algorithm - The algorithm to test with
 * @returns {boolean} - A boolean value indicating the validity of two Keys.
 * @remarks This is a helper function used to check if a certain private key relates to a certain public key
 */
export function checkKeyPair(privateKey: Key | string, publicKey: Key | string, signer: Signer, verifier: Verifier, algorithm: ALGORITHMS): boolean{
    const message = 'some test message';

    let signature = signer.sign(message, privateKey, algorithm);
    return verifier.verify(message, signature, publicKey, algorithm);
}

/**
 * @param {string} alg - Name of the algorithm as a string
 * @returns {ALGORITHMS} - Related enum type of the algorihm
 * @remarks This function is used to convert an algorithm name given as a string to a ALGORITHM value 
 */
export function getAlgorithm(alg: string): ALGORITHMS{
    return ALGORITHMS[alg.toUpperCase() as keyof typeof ALGORITHMS];
}

/**
 * @param {string} format - Name of the key format as a string
 * @returns {KEY_FORMATS} - Related enum type of the key format
 * @remarks This function is used to convert a key format given as a string to a KEY_FORMAT value 
 */
export function getKeyFormat(format: string): KEY_FORMATS{
    return KEY_FORMATS[format.toUpperCase() as keyof typeof KEY_FORMATS];
}

/**
 * @param {string} kty - Name of the key type as a string
 * @returns {KTYS} - Related enum type of the key type
 * @remarks This function is used to convert a key type name given as a string to a KTYS value
 */
export function getKeyType(kty: string): KTYS{
    return KTYS[kty.toUpperCase() as keyof typeof KTYS];
}