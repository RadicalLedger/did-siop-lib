"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var did_resolver_base_1 = require("./did_resolver_base");
var did_resolver_key_1 = require("./did_resolver_key");
var commons_1 = require("./commons");
var did_resolver_1 = require("did-resolver");
var ethr_did_resolver_1 = require("ethr-did-resolver");
var globals_1 = require("../globals");
var axios = require('axios').default;
/**
 * @classdesc A Resolver class which combines several other Resolvers in chain.
 * A given DID is tried with each Resolver object and if fails, passed to the next one in the chain.
 * @property {any[]} resolvers - An array to contain instances of other classes which implement DidResolver class.
 * @extends {DidResolver}
 */
var CombinedDidResolver = /** @class */ (function (_super) {
    __extends(CombinedDidResolver, _super);
    function CombinedDidResolver() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.resolvers = [];
        return _this;
    }
    /**
     *
     * @param {any} resolver - A resolver instance to add to the chain.
     * @returns {CombinedDidResolver} To use in fluent interface pattern.
     * @remarks Adds a given object to the resolvers array.
     */
    CombinedDidResolver.prototype.addResolver = function (resolver) {
        this.resolvers.push(resolver);
        return this;
    };
    CombinedDidResolver.prototype.resolveDidDocumet = function (did) {
        return __awaiter(this, void 0, void 0, function () {
            var doc, _i, _a, resolver, err_1;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        _i = 0, _a = this.resolvers;
                        _b.label = 1;
                    case 1:
                        if (!(_i < _a.length)) return [3 /*break*/, 6];
                        resolver = _a[_i];
                        _b.label = 2;
                    case 2:
                        _b.trys.push([2, 4, , 5]);
                        return [4 /*yield*/, resolver.resolve(did)];
                    case 3:
                        doc = _b.sent();
                        if (!doc) {
                            return [3 /*break*/, 5];
                        }
                        else {
                            return [2 /*return*/, doc];
                        }
                        return [3 /*break*/, 5];
                    case 4:
                        err_1 = _b.sent();
                        return [3 /*break*/, 5];
                    case 5:
                        _i++;
                        return [3 /*break*/, 1];
                    case 6: throw new Error(commons_1.ERRORS.DOCUMENT_RESOLUTION_ERROR);
                }
            });
        });
    };
    /**
     *
     * @param {string} did - DID to resolve the DID Document for.
     * @returns A promise which resolves to a {DidDocument}
     * @override resolve(did) method of the {DidResolver}
     * @remarks Unlike other resolvers this class can resolve Documents for many DID Methods.
     * Therefore the check in the parent class needs to be overridden.
     */
    CombinedDidResolver.prototype.resolve = function (did) {
        return this.resolveDidDocumet(did);
    };
    return CombinedDidResolver;
}(did_resolver_base_1.DidResolver));
/**
 * @classdesc Resolver class for Ethereum DIDs
 * @extends {DidResolver}
 */
var EthrDidResolver = /** @class */ (function (_super) {
    __extends(EthrDidResolver, _super);
    function EthrDidResolver() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    EthrDidResolver.prototype.resolveDidDocumet = function (did) {
        return __awaiter(this, void 0, void 0, function () {
            var providerConfig, ethrDidResolver, didResolver, result, didDoc, e_1;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        providerConfig = { name: "rinkeby", rpcUrl: 'https://rinkeby.infura.io/v3/e0a6ac9a2c4a4722970325c36b728415' };
                        ethrDidResolver = ethr_did_resolver_1.getResolver(providerConfig);
                        didResolver = new did_resolver_1.Resolver(ethrDidResolver);
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 3, , 4]);
                        return [4 /*yield*/, didResolver.resolve(did)];
                    case 2:
                        result = _a.sent();
                        didDoc = __assign({}, result.didDocument);
                        return [2 /*return*/, didDoc];
                    case 3:
                        e_1 = _a.sent();
                        return [2 /*return*/, undefined];
                    case 4: return [2 /*return*/];
                }
            });
        });
    };
    return EthrDidResolver;
}(did_resolver_base_1.DidResolver));
/**
 * @classdesc Resolver class which is based on the endpoint of https://dev.uniresolver.io/.
 * Can be used resolve Documents for any DID Method supported by the service.
 * @extends {DidResolver}
 */
var UniversalDidResolver = /** @class */ (function (_super) {
    __extends(UniversalDidResolver, _super);
    function UniversalDidResolver() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    UniversalDidResolver.prototype.resolveDidDocumet = function (did) {
        return __awaiter(this, void 0, void 0, function () {
            var returned;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, axios.get('https://dev.uniresolver.io/1.0/identifiers/' + did)];
                    case 1:
                        returned = _a.sent();
                        return [2 /*return*/, returned.data.didDocument];
                }
            });
        });
    };
    /**
     *
     * @param {string} did - DID to resolve the DID Document for.
     * @returns A promise which resolves to a {DidDocument}
     * @override resolve(did) method of the {DidResolver}
     * @remarks Unlike other resolvers this class can resolve Documents for many DID Methods.
     * Therefore the check in the parent class needs to be overridden.
     */
    UniversalDidResolver.prototype.resolve = function (did) {
        return this.resolveDidDocumet(did);
    };
    return UniversalDidResolver;
}(did_resolver_base_1.DidResolver));
/**
 * @exports CombinedDidResolver An instance of CombinedResolver which includes resolvers for currenlty implemented DID Methods.
 */
exports.combinedDidResolver = new CombinedDidResolver('all')
    .addResolver(new EthrDidResolver('ethr'))
    // .addResolver(new KeyDidResolver('key'))
    .addResolver(new did_resolver_key_1.KeyDidResolver2('key', globals_1.CRYPTO_SUITES.Ed25519VerificationKey2018))
    .addResolver(new did_resolver_key_1.KeyDidResolver2('key', globals_1.CRYPTO_SUITES.Ed25519VerificationKey2020))
    .addResolver(new UniversalDidResolver('uniresolver'));
//# sourceMappingURL=resolvers.js.map