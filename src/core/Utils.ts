import { Key } from "./JWKUtils";
import { ALGORITHMS } from "./globals";
import { Signer } from "./Signers";
import { Verifier } from "./Verifiers";

export function leftpad(data: any, size: number = 64) {
    if (data.length === size) return data
    return '0'.repeat(size - data.length) + data
}

export function checkKeyPair(privateKey: Key | string, publicKey: Key | string, signer: Signer, verifier: Verifier, algorithm: ALGORITHMS): boolean{
    const message = 'some test message';

    let signature = signer.sign(message, privateKey, algorithm);
    return verifier.verify(message, signature, publicKey, algorithm);
}