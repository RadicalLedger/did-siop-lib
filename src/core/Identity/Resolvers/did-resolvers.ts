import { DidResolver } from "./did-resolver-base";
import { EthrDidResolver } from "./did-resolver-ethr";
import { KeyDidResolver } from "./did-resolver-key";
import { UniversalDidResolver } from "./did-resolver-uniresolver";

export enum DidResolverType {
  key = "key",
  ethr = "ethr",
  uni = "uni",
}

export abstract class DidResolvers {
  public static getDidResolver(
    type: DidResolverType,
    methodName: string,
    cryptoSuite?: string
  ): DidResolver {
    let resolver: unknown;
    switch (type) {
      case DidResolverType.ethr:
        resolver = new EthrDidResolver(methodName, cryptoSuite);
        break;
      case DidResolverType.key:
        resolver = new KeyDidResolver(methodName, cryptoSuite);
        break;
      case DidResolverType.uni:
        resolver = new UniversalDidResolver(methodName, cryptoSuite);
        break;
      default:
        resolver = new UniversalDidResolver(methodName, cryptoSuite);
    }
    return resolver as DidResolver;
  }

  public static getDidResolvers(
    m: { type: DidResolverType; methodName: string; cryptoSuite?: string }[]
  ) {
    return m.map((e) =>
      this.getDidResolver(e.type, e.methodName, e.cryptoSuite)
    );
  }
}
