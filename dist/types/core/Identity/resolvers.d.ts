import { DidDocument } from "./commons";
declare abstract class DidResolver {
    protected methodName: string;
    constructor(methodName: string);
    abstract resolveDidDocumet(did: string): Promise<DidDocument>;
    resolve(did: string): Promise<DidDocument>;
}
declare class CombinedDidResolver extends DidResolver {
    private resolvers;
    addResolver(resolver: any): CombinedDidResolver;
    resolveDidDocumet(did: string): Promise<DidDocument>;
    resolve(did: string): Promise<DidDocument>;
}
export declare const combinedDidResolver: CombinedDidResolver;
export {};
