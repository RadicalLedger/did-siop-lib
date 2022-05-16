import { DidResolver } from "./did_resolver_base";
import { DidDocument } from "../commons";
/**
 * @classdesc Resolver class which is based on the endpoint of https://dev.uniresolver.io/.
 * Can be used resolve Documents for any DID Method supported by the service.
 * @extends {DidResolver}
 */
export declare class UniversalDidResolver extends DidResolver {
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
