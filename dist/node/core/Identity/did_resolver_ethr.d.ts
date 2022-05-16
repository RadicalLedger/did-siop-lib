import { DidResolver } from "./did_resolver_base";
import { DidDocument } from "./commons";
/**
 * @classdesc Resolver class for Ethereum DIDs
 * @extends {DidResolver}
 */
export declare class EthrDidResolver extends DidResolver {
    resolveDidDocumet(did: string): Promise<DidDocument | undefined>;
}
