import { DidDocument } from "./commons";
/**
 * @classdesc An abstract class which defines the interface for Resolver classes.
 * Resolvers are used to resolve the Decentralized Identity Document for a given DID.
 * Any extending child class must implement resolveDidDocumet(did) method.
 * @property {string} methodName - Name of the specific DID Method. Used as a check to resolve only DIDs related to this DID Method.
 */
declare abstract class DidResolver {
    protected methodName: string;
    /**
     * @constructor
     * @param {string} methodName - Name of the specific DID Method.
     */
    constructor(methodName: string);
    /**
     *
     * @param {string} did - DID to resolve the DID Document for.
     * @returns A promise which resolves to a {DidDocument}
     * @remarks Any inheriting child class must implement this abstract method. Relates to the Read operation of the DID Method.
     */
    abstract resolveDidDocumet(did: string): Promise<DidDocument | undefined>;
    /**
     *
     * @param {string} did - DID to resolve the DID Document for.
     * @returns A promise which resolves to a {DidDocument}
     * @remarks A wrapper method which make use of methodName property and resolveDidDocumet(did) method
     * to resolve documents for related DIDs only. Throws an error for DIDs of other DID Methods.
     */
    resolve(did: string): Promise<DidDocument | undefined>;
}
/**
 * @classdesc A Resolver class which combines several other Resolvers in chain.
 * A given DID is tried with each Resolver object and if fails, passed to the next one in the chain.
 * @property {any[]} resolvers - An array to contain instances of other classes which implement DidResolver class.
 * @extends {DidResolver}
 */
declare class CombinedDidResolver extends DidResolver {
    private resolvers;
    /**
     *
     * @param {any} resolver - A resolver instance to add to the chain.
     * @returns {CombinedDidResolver} To use in fluent interface pattern.
     * @remarks Adds a given object to the resolvers array.
     */
    addResolver(resolver: any): CombinedDidResolver;
    resolveDidDocumet(did: string): Promise<DidDocument>;
    /**
     *
     * @param {string} did - DID to resolve the DID Document for.
     * @returns A promise which resolves to a {DidDocument}
     * @override resolve(did) method of the {DidResolver}
     * @remarks Unlike other resolvers this class can resolve Documents for many DID Methods.
     * Therefore the check in the parent class needs to be overridden.
     */
    resolve(did: string): Promise<DidDocument>;
}
/**
 * @exports CombinedDidResolver An instance of CombinedResolver which includes resolvers for currenlty implemented DID Methods.
 */
export declare const combinedDidResolver: CombinedDidResolver;
export {};
