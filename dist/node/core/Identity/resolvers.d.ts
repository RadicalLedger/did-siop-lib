import { DidDocument } from "./commons";
import { DidResolver } from "./did_resolver_base";
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
