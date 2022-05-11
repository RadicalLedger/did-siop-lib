import { DidResolver } from "./did_resolver_base";
import { DidDocument } from "./commons";
/**
 * @classdesc Resolver class for did:key
 * @extends {DidResolver}
 */
export declare class KeyDidResolver2 extends DidResolver {
    resolveDidDocumet(did: string): Promise<DidDocument | undefined>;
}
