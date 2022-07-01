import { DidDocument, DidVerificationKey, ERRORS } from "./commons";
import { DidResolver } from "./resolvers/did-resolver-base";
import { DidVerificationKeyExtractor, uniExtractor } from "./key-extractors";
import * as Resolvers from "./resolvers";

/**
 * @classdesc A class to represent a Decentralized Identity.
 * @property {DidDocument} doc - Decentralized Identity Document. Initialized with empty values in the constructor. Assigned later using resolve(did) method.
 * @property {DidVerificationKey[]} KeySet - A list of verification keys listed in the did-doc. Initialied empty in the constructor. Filled later using extractAuthenticationKeys method.
 */
export class Identity {
  private doc: DidDocument;
  private keySet: DidVerificationKey[];
  private combinedDidResolver!: Resolvers.CombinedDidResolver;

  /**
   * @constructor
   */
  constructor() {
    this.doc = {
      "@context": "",
      id: "",
      authentication: [],
    };
    this.keySet = [];
    this.combinedDidResolver = new Resolvers.CombinedDidResolver("all");
  }

  /**
   *
   * @param {DidResolver[]} resolvers - Array of resolvers derived from DidResolver to be use in resolving a given DID
   * @remarks The combinedResolver is used to resolve did-doc.
   */
  addResolvers(resolvers: DidResolver[]) {
    for (let resolver in resolvers) {
      this.combinedDidResolver.addResolver(resolvers[resolver]);
    }
  }

  /**
   *
   * @returns {DidResolver[]} returns currently available DidResolver array
   * @remarks Return currently available resolvers array.
   */
  getResolvers(): any[] {
    return this.combinedDidResolver.getResolvers();
  }

  /**
   * @returns {void}
   * @remarks Remove all resolvers in combined resolver (mostly used when UnitTesting)
   */
  removeAllResolvers() {
    this.combinedDidResolver.removeAllResolvers();
  }

  /**
   *
   * @param {string} did - A Decentralized Identity to resolve
   * @returns A promise which resolves to the id field of the related Decentralized Idenity Document (did-doc)
   * @remarks The combinedResolver is used to resolve did-doc.
   */
  async resolve(did: string): Promise<string> {
    let result: DidDocument;
    try {
      result = await this.combinedDidResolver.resolve(did);
    } catch (err) {
      throw new Error(ERRORS.DOCUMENT_RESOLUTION_ERROR);
    }

    if (
      result &&
      //result.data.didDocument['@context'] === 'https://w3id.org/did/v1' &&
      result.id == did &&
      result.authentication &&
      result.authentication.length > 0
    ) {
      this.doc = result;
      this.keySet = [];
      return this.doc.id;
    }
    throw new Error(ERRORS.INVALID_DID_ERROR);
  }

  /**
   * @returns true/false to indicate whether the Identity has a resolved did-doc or not
   */
  isResolved() {
    return this.doc.id !== "";
  }

  /**
   *
   * @param {DidVerificationKeyExtractor} [extractor] - The extractor to use when extracting keys. If not provided, uniExtractor is used.
   * @returns An array of DidVerificationKey objects
   * @remarks resolve(did) method must be called before calling this method. This method returns the value of keySet property. If keySet is
   * empty then this method will extract cryptographic keys and related information from the 'authentication' field of did-doc and populate keySet property.
   * https://www.w3.org/TR/did-core/#authentication
   * 'authentication' field is an array and contains Verification Methods in following forms
   *  - A full method which has 'id' and 'type' fields
   *  - A string
   *  - An object with 'type' field and references to 'publicKey' field of did-doc as an array.
   */
  extractAuthenticationKeys(
    extractor?: DidVerificationKeyExtractor
  ): DidVerificationKey[] {
    if (!extractor) extractor = uniExtractor;
    if (!this.isResolved()) throw new Error(ERRORS.UNRESOLVED_DOCUMENT);
    if (this.keySet.length === 0) {
      for (let method of this.doc.authentication) {
        if (method.id && method.type) {
          try {
            this.keySet.push(extractor.extract(method));
          } catch (err) {
            continue;
          }
        }

        if (method.publicKey) {
          if (typeof method.publicKey === "string") {
            for (let pub of this.doc.publicKey) {
              if (
                pub.id === method.publicKey ||
                pub.id === this.doc.id + method.publicKey
              ) {
                try {
                  this.keySet.push(extractor.extract(pub));
                } catch (err) {
                  continue;
                }
              }
            }
          } else {
            for (let key of method.publicKey) {
              for (let pub of this.doc.publicKey) {
                if (pub.id === key || pub.id === this.doc.id + key) {
                  try {
                    this.keySet.push(extractor.extract(pub));
                  } catch (err) {
                    continue;
                  }
                }
              }
            }
          }
        }
        if (typeof method === "string") {
          for (let pub of this.doc.verificationMethod) {
            if (pub.id === method) {
              try {
                this.keySet.push(extractor.extract(pub));
              } catch (err) {
                continue;
              }
            }
          }
          //Implement other verification methods here
        }
      }
    }
    return this.keySet;
  }

  /**
   * @returns {DidDocument} The doc property.
   */
  getDocument(): DidDocument {
    return this.doc;
  }

  /**
   *
   * @param {DidDocument} doc
   * @param {string} did - DID related to the doc param
   * @remarks Can be used to set the doc property manually without resolving.
   */
  setDocument(doc: DidDocument, did: string) {
    if (
      //doc['@context'] === 'https://w3id.org/did/v1' &&
      doc.id == did &&
      doc.authentication &&
      doc.authentication.length > 0
    ) {
      this.doc = doc;
    } else {
      throw new Error(ERRORS.INVALID_DOCUMENT);
    }
  }
}

export {
  DidDocument,
  DidVerificationKey,
  DidVerificationKeyMethod,
  ERRORS,
} from "./commons";
export { DidVerificationKeyExtractor, uniExtractor } from "./key-extractors";
export { Resolvers };
