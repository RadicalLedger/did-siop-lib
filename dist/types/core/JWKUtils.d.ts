import { KEY_FORMATS, KTYS } from './globals';
export declare const ERRORS: Readonly<{
    INVALID_KEY_FORMAT: string;
    NO_PRIVATE_KEY: string;
    INVALID_KEY: string;
    INVALID_KEY_SET: string;
    NO_MATCHING_KEY: string;
    URI_ERROR: string;
    KEY_EXISTS: string;
}>;
export declare namespace KeyObjects {
    interface BasicKeyObject {
        kty: string;
        use: string;
        kid: string;
        alg: string;
    }
    interface RSAPrivateKeyObject extends BasicKeyObject {
        p: string;
        q: string;
        d: string;
        e: string;
        qi: string;
        dp: string;
        dq: string;
        n: string;
    }
    interface RSAPublicKeyObject extends BasicKeyObject {
        e: string;
        n: string;
    }
    interface ECPrivateKeyObject extends BasicKeyObject {
        crv: string;
        d: string;
        x: string;
        y: string;
    }
    interface ECPublicKeyObject extends BasicKeyObject {
        crv: string;
        x: string;
        y: string;
    }
    interface OKPPrivateKeyObject extends BasicKeyObject {
        crv: string;
        d: string;
        x: string;
    }
    interface OKPPublicKeyObject extends BasicKeyObject {
        crv: string;
        x: string;
    }
    interface SymmetricKeyObject extends BasicKeyObject {
        k: string;
    }
}
export declare namespace KeyInputs {
    interface KeyInfo {
        key: string;
        kid: string;
        use: string;
        kty: string;
        alg?: string;
        format: KEY_FORMATS;
        isPrivate: boolean;
    }
    type RSAPrivateKeyInput = KeyInfo | KeyObjects.RSAPrivateKeyObject;
    type RSAPublicKeyInput = KeyInfo | KeyObjects.RSAPublicKeyObject;
    type ECPrivateKeyInput = KeyInfo | KeyObjects.ECPrivateKeyObject;
    type ECPublicKeyInput = KeyInfo | KeyObjects.ECPublicKeyObject;
    type OKPPrivateKeyInput = KeyInfo | KeyObjects.OKPPrivateKeyObject;
    type OKPPublicKeyInput = KeyInfo | KeyObjects.OKPPublicKeyObject;
    type SymmetricKeyInput = KeyInfo | KeyObjects.SymmetricKeyObject;
}
export declare abstract class Key {
    protected kty: string;
    protected kid: string;
    protected use: string;
    protected alg: string;
    protected private: boolean;
    protected constructor(kid: string, kty: KTYS, use: string, alg?: string);
    isPrivate(): boolean;
    checkKid(kid: string): boolean;
    abstract toJWK(privateKey?: boolean): KeyObjects.BasicKeyObject;
    abstract getMinimalJWK(privateKey?: boolean): any;
    abstract exportKey(format: KEY_FORMATS): string;
}
export declare class RSAKey extends Key {
    private p?;
    private q?;
    private d?;
    private e;
    private qi?;
    private dp?;
    private dq?;
    private n;
    private constructor();
    static fromPublicKey(keyInput: KeyInputs.RSAPublicKeyInput): RSAKey;
    static fromPrivateKey(keyInput: KeyInputs.RSAPrivateKeyInput): RSAKey;
    static fromKey(keyInput: KeyInputs.RSAPublicKeyInput | KeyInputs.RSAPrivateKeyInput): RSAKey;
    static isPrivateKeyInput(keyInput: KeyInputs.RSAPublicKeyInput | KeyInputs.RSAPrivateKeyInput): boolean;
    toJWK(privateKey?: boolean): KeyObjects.RSAPrivateKeyObject | KeyObjects.RSAPublicKeyObject;
    private toPEM;
    exportKey(format: KEY_FORMATS): string;
    getMinimalJWK(privateKey?: boolean): {
        d: string | undefined;
        dp: string | undefined;
        dq: string | undefined;
        e: string;
        kty: string;
        n: string;
        p: string | undefined;
        q: string | undefined;
        qi: string | undefined;
    } | {
        e: string;
        kty: string;
        n: string;
        d?: undefined;
        dp?: undefined;
        dq?: undefined;
        p?: undefined;
        q?: undefined;
        qi?: undefined;
    };
}
export declare class ECKey extends Key {
    private crv;
    private x;
    private y;
    private d?;
    private constructor();
    static fromPublicKey(keyInput: KeyInputs.ECPublicKeyInput): ECKey;
    static fromPrivateKey(keyInput: KeyInputs.ECPrivateKeyInput): ECKey;
    static fromKey(keyInput: KeyInputs.ECPublicKeyInput | KeyInputs.ECPrivateKeyInput): ECKey;
    static isPrivateKeyInput(keyInput: KeyInputs.ECPublicKeyInput | KeyInputs.ECPrivateKeyInput): boolean;
    toJWK(privateKey?: boolean): KeyObjects.ECPrivateKeyObject | KeyObjects.ECPublicKeyObject;
    exportKey(format: KEY_FORMATS): string;
    getMinimalJWK(privateKey?: boolean): {
        crv: string;
        d: string | undefined;
        kty: string;
        x: string;
        y: string;
    } | {
        crv: string;
        kty: string;
        x: string;
        y: string;
        d?: undefined;
    };
}
export declare class OKP extends Key {
    private crv;
    private x;
    private d?;
    private constructor();
    static fromPublicKey(keyInput: KeyInputs.OKPPublicKeyInput): OKP;
    static fromPrivateKey(keyInput: KeyInputs.OKPPrivateKeyInput): OKP;
    static fromKey(keyInput: KeyInputs.OKPPublicKeyInput | KeyInputs.OKPPrivateKeyInput): OKP;
    static isPrivateKeyInput(keyInput: KeyInputs.OKPPublicKeyInput | KeyInputs.OKPPrivateKeyInput): boolean;
    toJWK(privateKey?: boolean): KeyObjects.OKPPrivateKeyObject | KeyObjects.OKPPublicKeyObject;
    exportKey(format: KEY_FORMATS): string;
    getMinimalJWK(privateKey?: boolean): {
        crv: string;
        d: string | undefined;
        kty: string;
        x: string;
    } | {
        crv: string;
        kty: string;
        x: string;
        d?: undefined;
    };
}
export declare class KeySet {
    private ketSet;
    private uri;
    setKeys(keySet: KeyObjects.BasicKeyObject[]): void;
    setURI(uri: string): Promise<void>;
    getKey(kid: string): Key[];
    addKey(key: KeyObjects.BasicKeyObject): void;
    removeKey(kid: string): void;
    size(): number;
}
export declare function calculateThumbprint(minimalJWK: any): string;
