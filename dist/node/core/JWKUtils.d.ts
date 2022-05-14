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
/**
 * @classdesc An abstract class which defines the generic interface of a asymmetric cryptographic key pair.
 * @property {string} kty - Type of the specific cryptographic key
 * @property {string} kid - ID of the specific cryptographic key
 * @property {string} use - Cryptographic function the key is used in - encryption/signing
 * @property {string} alg - Algorithm with which the key is used
 * @property {boolean} private - Whether the key has the private part of asymmetric key pair
 */
export declare abstract class Key {
    protected kty: string;
    protected kid: string;
    protected use: string;
    protected alg: string;
    protected private: boolean;
    /**
     * @protected
     * @constructor
     * @param {string} kid
     * @param {KTYS} kty
     * @param {string} use
     * @param {string} [alg]
     * @remarks Constructor initializes the generic information. Initialization of specific information needs to be done by subclasses.
     * It is a protected method and can only be used inside the class itself or inside subclasses.
     */
    protected constructor(kid: string, kty: KTYS, use: string, alg?: string);
    /**
     * @returns {boolean} private
     * @remarks This method is used to check if this key has private part
     */
    isPrivate(): boolean;
    /**
     *
     * @param {string} kid - A string to compare against the kid value of this key.
     * @returns {boolean} - A boolean value indicating match/mismatch
     * @remarks This method is useful when a key with specific kid needs to be filtered out from a list of keys.
     */
    checkKid(kid: string): boolean;
    /**
     * @param {boolean} privateKey - To indicate whether to include private part of the key. If not provided, only the public part is returned.
     * @returns {BasicKeyObject} - An object of any class which implements KeyObjects.BasicKeyObject
     * @remarks This method is used to get this key as a JWK. Subclasses needs to implement this due to them having specific information other than those
     * in this class.
     */
    abstract toJWK(privateKey?: boolean): KeyObjects.BasicKeyObject;
    /**
     * @param {boolean} privateKey - To indicate whether to include private part of the key. If not provided, only the public part is returned.
     * @returns {any}
     * @remarks Same as toJWK() but only returns the essential information and prunes the other.
     */
    abstract getMinimalJWK(privateKey?: boolean): any;
    /**
     *
     * @param {KEY_FORMATS} format - Format to which the key needs to be exported
     * @returns {string}
     * @remarks A certain cryptographic key can exist in several formats. This method is used to convert this key into a desired format.
     * Subclasses needs to implement this due to them having specific information other than those in this class.
     */
    abstract exportKey(format: KEY_FORMATS): string;
}
/**
 * @classdesc A class used to represent an RSA key pair
 * @property {string} [p] - First Prime Factor
 * @property {string} [q] - Second Prime Factor
 * @property {string} [d] - RSA private exponent
 * @property {string} e - RSA public exponent
 * @property {string} [qi] - First Chinese Remainder Theorem Coefficient
 * @property {string} [dp] - First Factor Chinese Remainder Theorem Exponent
 * @property {string} [dq] - Second Factor Chinese Remainder Theorem Exponent
 * @property {string} n - RSA public modulus
 * @extends {Key}
 */
export declare class RSAKey extends Key {
    private p?;
    private q?;
    private d?;
    private e;
    private qi?;
    private dp?;
    private dq?;
    private n;
    /**
     * @private
     * @constructor
     * @param {string} kid
     * @param {KTYS} kty
     * @param {string} n
     * @param {string} e
     * @param {string} use
     * @param {string} alg
     * @remarks Passes generic information to super class constructor. Initializes specific information. Called within static methods.
     */
    private constructor();
    /**
     * @static
     * @param {KeyInputs.RSAPublicKeyInput} keyInput - Object which contains information to initialze a RSA public key object
     * @returns {RSAKey} - An RSAKey object
     * @remarks This static method creates and returns an RSAKey object which has only the public information
     */
    static fromPublicKey(keyInput: KeyInputs.RSAPublicKeyInput): RSAKey;
    /**
     * @static
     * @param {KeyInputs.RSAPrivateKeyInput} keyInput - Object which contains information to initialze a RSA private key object
     * @returns {RSAKey} - An RSAKey object
     * @remarks This static method creates and returns an RSAKey object which has both public and private information
     */
    static fromPrivateKey(keyInput: KeyInputs.RSAPrivateKeyInput): RSAKey;
    /**
     * @static
     * @param {KeyInputs.RSAPublicKeyInput | KeyInputs.RSAPrivateKeyInput} keyInput - Object which contains information to initialze a
     * private or public RSA key object
     * @returns {RSAKey} - An RSAKey object
     * @remarks Wrapper method which accepts either public or private key information and returns a RSA key object
     */
    static fromKey(keyInput: KeyInputs.RSAPublicKeyInput | KeyInputs.RSAPrivateKeyInput): RSAKey;
    /**
     * @static
     * @param {KeyInputs.RSAPublicKeyInput | KeyInputs.RSAPrivateKeyInput} keyInput - Object which contains information to initialze a
     * private or public RSA key object
     * @returns {boolean} - Boolean which indicates whether the input contains private information
     * @remarks This method is used to determine specific key input has private information
     */
    static isPrivateKeyInput(keyInput: KeyInputs.RSAPublicKeyInput | KeyInputs.RSAPrivateKeyInput): boolean;
    toJWK(privateKey?: boolean): KeyObjects.RSAPrivateKeyObject | KeyObjects.RSAPublicKeyObject;
    /**
     * @param {'pkcs8'|'pkcs1'} [format = 'pkcs8'] - PEM standard
     * @returns {string} This key in PEM format
     * @remarks This method is used to get the key encoded in PEM format
     */
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
/**
 * @classdesc A class used to represent Elliptic Curve cryptographic key
 * @property {string} crv - Cryptographic curve used with the key
 * @property {string} x - x coordinate for the public key point
 * @property {string} y - y coordinate for the public key point
 * @property {string} [d] - Private key value
 */
export declare class ECKey extends Key {
    private crv;
    private x;
    private y;
    private d?;
    /**
     * @private
     * @constructor
     * @param {string} kid
     * @param {KTYS} kty
     * @param {string} crv
     * @param {string} x
     * @param {string} y
     * @param {string} use
     * @param {string} alg
     * @remarks Passes generic information to super class constructor. Initializes specific information. Called within static methods.
     */
    private constructor();
    /**
     * @static
     * @param {KeyInputs.ECPublicKeyInput} keyInput - Object which contains information to initialze a EC public key object
     * @returns {ECKey} - An EC key object
     * @remarks This static method creates and returns an ECKey object which has only the public information
     */
    static fromPublicKey(keyInput: KeyInputs.ECPublicKeyInput): ECKey;
    /**
     * @static
     * @param {KeyInputs.ECPrivateKeyInput} keyInput - Object which contains information to initialze a EC private key object
     * @returns {ECKey} - An EC key object
     * @remarks This static method creates and returns an ECKey object which has public and private information
     */
    static fromPrivateKey(keyInput: KeyInputs.ECPrivateKeyInput): ECKey;
    /**
     * @static
     * @param {KeyInputs.ECPublicKeyInput | KeyInputs.ECPrivateKeyInput} keyInput - Object which contains information to initialze a
     * private or public EC key object
     * @returns {ECKey} - An EC Key object
     * @remarks Wrapper method which accepts either public or private key information and returns an EC key object
     */
    static fromKey(keyInput: KeyInputs.ECPublicKeyInput | KeyInputs.ECPrivateKeyInput): ECKey;
    /**
     * @static
     * @param {KeyInputs.ECPublicKeyInput | KeyInputs.ECPrivateKeyInput} keyInput - Object which contains information to initialze a
     * private or public EC key object
     * @returns {boolean} - A boolean which indicates whether the input contains private information
     * @remarks This method is used to determine specific key input has private information
     */
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
/**
 * @classdesc A class used to represent Octet Key Pair (Edwards curve) cryptographic key
 * @property {string} crv - Cryptographic curve used with the key
 * @property {string} x - x coordinate for the public key point
 * @property {string} [d] - Private key value
 */
export declare class OKP extends Key {
    private crv;
    private x;
    private d?;
    /**
     * @private
     * @constructor
     * @param {string} kid
     * @param {KTYS} kty
     * @param {string} crv
     * @param {string} x
     * @param {string} use
     * @param {string} alg
     * @remarks Passes generic information to super class constructor. Initializes specific information. Called within static methods.
     */
    private constructor();
    /**
     * @static
     * @param {KeyInputs.OKPPublicKeyInput} keyInput - Object which contains information to initialze a OKP public key object
     * @returns {OKP} - An OKP object
     * @remarks This static method creates and returns an OKP object which has only the public information
     */
    static fromPublicKey(keyInput: KeyInputs.OKPPublicKeyInput): OKP;
    /**
     * @static
     * @param {KeyInputs.OKPPrivateKeyInput} keyInput - Object which contains information to initialze a OKP private key object
     * @returns {ECKey} - An OKP object
     * @remarks This static method creates and returns an OKP object which has public and private information
     */
    static fromPrivateKey(keyInput: KeyInputs.OKPPrivateKeyInput): OKP;
    /**
     * @static
     * @param {KeyInputs.OKPPublicKeyInput | KeyInputs.OKPPrivateKeyInput} keyInput - Object which contains information to initialze a
     * private or public OKP object
     * @returns {ECKey} - An OKP object
     * @remarks Wrapper method which accepts either public or private key information and returns an OKP object
     */
    static fromKey(keyInput: KeyInputs.OKPPublicKeyInput | KeyInputs.OKPPrivateKeyInput): OKP;
    /**
     * @static
     * @param {KeyInputs.OKPPublicKeyInput | KeyInputs.OKPPrivateKeyInput} keyInput - Object which contains information to initialze a
     * private or public OKP object
     * @returns {boolean} - A boolean which indicates whether the input contains private information
     * @remarks This method is used to determine specific key input has private information
     */
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
/**
 * @classdesc A class used to represent a JSON Web Key Set (JWKS)
 * @property {Key[]} keySet - An array of Key objects. Initially set to empty.
 * @property {string} uri - An URI from which a key set can be retrieved.
 */
export declare class KeySet {
    private ketSet;
    private uri;
    /**
     * @param {KeyObjects.BasicKeyObject[]} keySet - An array of KeyObjects.BasicKeyObject objects.
     * @remarks This method accepts an array of KeyObjects.BasicKeyObject objects and converts them to Key objects of related types.
     */
    setKeys(keySet: KeyObjects.BasicKeyObject[]): void;
    /**
     * @param {string} uri - An URI from which a key set can be retrieved.
     * @remarks This method sets the uri property and tries to retrieve a key set from it
     */
    setURI(uri: string): Promise<void>;
    /**
     * @param {string} kid - ID of the key which needs to be retrieved from the set
     * @returns {Key[]} - A Key object(s) which has kid values matching given ID
     * @remarks This method can be used to filter out a Key or set of Keys which has a specific kid value
     */
    getKey(kid: string): Key[];
    /**
     * @param {KeyObjects.BasicKeyObject} key
     * @remarks This method is used to add a new Key to the set
     */
    addKey(key: KeyObjects.BasicKeyObject): void;
    /**
     * @param {string} kid - The ID value of the Key which needs to be removed from the set
     * @remarks This method is used to remove a Key or set of Keys by kid value
     */
    removeKey(kid: string): void;
    /**
     * @returns {number} The number of keys in the set
     * @remarks This method returms the size of the Key set
     */
    size(): number;
}
/**
 * @param {any} minimalJWK - The JWK object to calculate the thumbprint
 * @returns {string} - JWK thumbprint of the given JWK
 * @remarks This standalone method is used to calculate the thumbprint (https://tools.ietf.org/html/rfc7638#section-3)
 * for a given JWK
 */
export declare function calculateThumbprint(minimalJWK: any): string;
