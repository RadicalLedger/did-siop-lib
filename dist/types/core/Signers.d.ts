/// <reference types="node" />
import { Key, RSAKey, ECKey, OKP } from './JWKUtils';
import { ALGORITHMS } from './globals';
export declare const ERRORS: Readonly<{
    NO_PRIVATE_KEY: string;
    INVALID_ALGORITHM: string;
}>;
export declare abstract class Signer {
    abstract sign(message: string, key: Key | string, algorithm?: ALGORITHMS): Buffer;
}
export declare class RSASigner extends Signer {
    sign(message: string, key: RSAKey, algorithm: ALGORITHMS): Buffer;
}
export declare class ECSigner extends Signer {
    sign(message: string, key: ECKey, algorithm: ALGORITHMS): Buffer;
}
export declare class OKPSigner extends Signer {
    sign(message: string, key: OKP, algorithm: ALGORITHMS): Buffer;
}
export declare class ES256KRecoverableSigner extends Signer {
    sign(message: string, key: ECKey | string): Buffer;
}
