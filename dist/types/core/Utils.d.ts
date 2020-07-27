import { Key } from "./JWKUtils";
import { ALGORITHMS, KEY_FORMATS, KTYS } from "./globals";
import { Signer } from "./Signers";
import { Verifier } from "./Verifiers";
export declare function leftpad(data: any, size?: number): any;
export declare function checkKeyPair(privateKey: Key | string, publicKey: Key | string, signer: Signer, verifier: Verifier, algorithm: ALGORITHMS): boolean;
export declare function getAlgorithm(alg: string): ALGORITHMS;
export declare function getKeyFormat(format: string): KEY_FORMATS;
export declare function getKeyType(kty: string): KTYS;
