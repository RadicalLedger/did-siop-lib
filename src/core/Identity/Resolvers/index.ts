import { DidDocument, ERRORS } from "../commons";
import { DidResolver } from "./did-resolver-base";
import { EthrDidResolver } from "./did-resolver-ethr";
import { KeyDidResolver } from "./did-resolver-key";
import { UniversalDidResolver } from "./did-resolver-uniresolver";
import { DidResolvers } from "./did-resolvers";

/**
 * @classdesc A Resolver class which combines several other Resolvers in chain.
 * A given DID is tried with each Resolver object and if fails, passed to the next one in the chain.
 * @property {any[]} resolvers - An array to contain instances of other classes which implement DidResolver class.
 * @extends {DidResolver}
 */
class CombinedDidResolver extends DidResolver {
  private resolvers: any[] = [];

  /**
   * @param {any} resolver - A resolver instance to add to the chain.
   * @returns {CombinedDidResolver} To use in fluent interface pattern.
   * @remarks Adds a given object to the resolvers array.
   */
  addResolver(resolver: any): CombinedDidResolver {
    this.resolvers.push(resolver);
    return this;
  }

  /**
   * @returns {DidResolver[]} returns currently available DidResolver array
   * @remarks Return currently available resolvers array.
   */
  getResolvers(): any[] {
    return this.resolvers;
  }

  /**
   * @returns {void}
   * @remarks Remove all resolvers (mostly used when UnitTesting)
   */
  removeAllResolvers() {
    this.resolvers = [];
  }

  async resolveDidDocumet(did: string): Promise<DidDocument> {
    let doc: DidDocument | undefined;

    if (this.resolvers.length == 0) {
      let uniResolver = new UniversalDidResolver("uniresolver");
      this.addResolver(uniResolver);
    }
    for (let resolver of this.resolvers) {
      try {
        doc = await resolver.resolve(did);
        if (!doc) {
          continue;
        } else {
          return doc;
        }
      } catch (err) {
        continue;
      }
    }
    throw new Error(ERRORS.DOCUMENT_RESOLUTION_ERROR);
  }

  /**
   *
   * @param {string} did - DID to resolve the DID Document for.
   * @returns A promise which resolves to a {DidDocument}
   * @override resolve(did) method of the {DidResolver}
   * @remarks Unlike other resolvers this class can resolve Documents for many DID Methods.
   * Therefore the check in the parent class needs to be overridden.
   */
  resolve(did: string): Promise<DidDocument> {
    return this.resolveDidDocumet(did);
  }
}

export {
  CombinedDidResolver,
  KeyDidResolver,
  EthrDidResolver,
  UniversalDidResolver,
  DidResolvers,
};
