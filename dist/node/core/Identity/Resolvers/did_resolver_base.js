"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/**
 * @classdesc An abstract class which defines the interface for Resolver classes.
 * Resolvers are used to resolve the Decentralized Identity Document for a given DID.
 * Any extending child class must implement resolveDidDocumet(did) method.
 * @property {string} methodName - Name of the specific DID Method. Used as a check to resolve only DIDs related to this DID Method.
 */
var DidResolver = /** @class */ (function () {
    /**
     * @constructor
     * @param {string} methodName - Name of the specific DID Method.
     */
    function DidResolver(methodName, cryto_suite) {
        this.methodName = methodName;
        this.cryto_suite = cryto_suite;
    }
    /**
     *
     * @param {string} did - DID to resolve the DID Document for.
     * @returns A promise which resolves to a {DidDocument}
     * @remarks A wrapper method which make use of methodName property and resolveDidDocumet(did) method
     * to resolve documents for related DIDs only. Throws an error for DIDs of other DID Methods.
     */
    DidResolver.prototype.resolve = function (did) {
        if (did.split(':')[1] !== this.methodName)
            throw new Error('Incorrect did method');
        return this.resolveDidDocumet(did, this.cryto_suite);
    };
    return DidResolver;
}());
exports.DidResolver = DidResolver;
//# sourceMappingURL=did_resolver_base.js.map