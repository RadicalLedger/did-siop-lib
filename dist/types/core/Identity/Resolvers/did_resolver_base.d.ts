import { DidDocument } from "../commons";
/**
 * @classdesc An abstract class which defines the interface for Resolver classes.
 * Resolvers are used to resolve the Decentralized Identity Document for a given DID.
 * Any extending child class must implement resolveDidDocumet(did) method.
 * @property {string} methodName - Name of the specific DID Method. Used as a check to resolve only DIDs related to this DID Method.
 */
export declare abstract class DidResolver {
    protected methodName: string;
    protected cryto_suite?: string | undefined;
    /**
     * @constructor
     * @param {string} methodName - Name of the specific DID Method.
     * @param {string} cryto_suite - Cryptographic suite to construct the DID.
     */
    constructor(methodName: string, cryto_suite?: string | undefined);
    /**
     *
     * @param {string} did - DID to resolve the DID Document for.
     * @returns A promise which resolves to a {DidDocument}
     * @remarks Any inheriting child class must implement this abstract method. Relates to the Read operation of the DID Method.
     */
    abstract resolveDidDocumet(did: string, cryto_suite?: string): Promise<DidDocument | undefined>;
    /**
     *
     * @param {string} did - DID to resolve the DID Document for.
     * @returns A promise which resolves to a {DidDocument}
     * @remarks A wrapper method which make use of methodName property and resolveDidDocumet(did) method
     * to resolve documents for related DIDs only. Throws an error for DIDs of other DID Methods.
     */
    resolve(did: string): Promise<DidDocument | undefined>;
}
