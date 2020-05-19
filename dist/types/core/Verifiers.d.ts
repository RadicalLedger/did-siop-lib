/// <reference types="node" />
import { Key, RSAKey, ECKey, OKP } from "./JWKUtils";
import { ALGORITHMS } from "./globals";
export declare const ERRORS: Readonly<{
    NO_PRIVATE_KEY: string;
    INVALID_ALGORITHM: string;
    INVALID_SIGNATURE: string;
}>;
export declare abstract class Verifier {
    abstract verify(msg: string, signature: Buffer, key: Key | string, algorithm?: ALGORITHMS): boolean;
}
export declare class RSAVerifier extends Verifier {
    verify(msg: string, signature: Buffer, key: RSAKey, algorithm?: ALGORITHMS | undefined): boolean;
}
export declare class ECVerifier extends Verifier {
    verify(msg: string, signature: Buffer, key: ECKey, algorithm?: ALGORITHMS | undefined): boolean;
}
export declare class OKPVerifier extends Verifier {
    verify(msg: string, signature: Buffer, key: OKP, algorithm?: ALGORITHMS | undefined): boolean;
}
export declare class ES256KRecoverableVerifier extends Verifier {
    verify(msg: string, signature: Buffer, key: ECKey | string): boolean;
}
