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
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var commons_1 = require("./commons");
var ethr_did_resolver_1 = require("ethr-did-resolver");
var base58 = __importStar(require("bs58"));
var multibase_1 = __importDefault(require("multibase"));
var multicodec_1 = __importDefault(require("multicodec"));
var ed2curve_1 = __importDefault(require("ed2curve"));
var axios = require('axios').default;
var DidResolver = /** @class */ (function () {
    function DidResolver(methodName) {
        this.methodName = methodName;
    }
    DidResolver.prototype.resolve = function (did) {
        if (did.split(':')[1] !== this.methodName)
            throw new Error('Incorrect did method');
        return this.resolve(did);
    };
    return DidResolver;
}());
var CombinedDidResolver = /** @class */ (function (_super) {
    __extends(CombinedDidResolver, _super);
    function CombinedDidResolver() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.resolvers = [];
        return _this;
    }
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
    CombinedDidResolver.prototype.resolve = function (did) {
        return this.resolveDidDocumet(did);
    };
    return CombinedDidResolver;
}(DidResolver));
var EthrDidResolver = /** @class */ (function (_super) {
    __extends(EthrDidResolver, _super);
    function EthrDidResolver() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    EthrDidResolver.prototype.resolveDidDocumet = function (did) {
        return __awaiter(this, void 0, void 0, function () {
            var providerConfig, resolve;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        providerConfig = { rpcUrl: 'https://ropsten.infura.io/v3/e0a6ac9a2c4a4722970325c36b728415' };
                        resolve = ethr_did_resolver_1.getResolver(providerConfig).ethr;
                        return [4 /*yield*/, resolve(did, {
                                did: did,
                                method: 'ethr',
                                id: did.split(':')[2],
                                didUrl: did
                            })];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    return EthrDidResolver;
}(DidResolver));
var KeyDidResolver = /** @class */ (function (_super) {
    __extends(KeyDidResolver, _super);
    function KeyDidResolver() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    KeyDidResolver.prototype.resolveDidDocumet = function (did) {
        if (!did) {
            throw new TypeError('"did" must be a string.');
        }
        var didAuthority = did.split('#')[0];
        var fingerprint = didAuthority.substr('did:key:'.length);
        var decodedFingerprint = multibase_1.default.decode(fingerprint);
        var unprefixed = multicodec_1.default.rmPrefix(decodedFingerprint);
        var publicKey = base58.encode(unprefixed);
        var keyId = did + '#' + fingerprint;
        var keyAgreementKeyBuffer = ed2curve_1.default.convertPublicKey(unprefixed);
        if (!keyAgreementKeyBuffer)
            throw new Error('Cannot derive keyAgreement');
        var keyAgreementKey = base58.encode(keyAgreementKeyBuffer);
        var keyAgreementIdBuffer = Buffer.alloc(2 + keyAgreementKeyBuffer.length);
        keyAgreementIdBuffer[0] = 0xec;
        keyAgreementIdBuffer[1] = 0x01;
        keyAgreementIdBuffer.set(keyAgreementKeyBuffer, 2);
        var keyAgreementId = did + '#' + 'z' + base58.encode(keyAgreementIdBuffer);
        var didDoc = {
            '@context': ['https://w3id.org/did/v0.11'],
            id: did,
            publicKey: [{
                    id: keyId,
                    type: 'Ed25519VerificationKey2018',
                    controller: did,
                    publicKeyBase58: publicKey
                }],
            authentication: [keyId],
            assertionMethod: [keyId],
            capabilityDelegation: [keyId],
            capabilityInvocation: [keyId],
            keyAgreement: [{
                    id: keyAgreementId,
                    type: 'X25519KeyAgreementKey2019',
                    controller: did,
                    publicKeyBase58: keyAgreementKey
                }]
        };
        console.log('resolved by did:key\n' + JSON.stringify(didDoc));
        return Promise.resolve(didDoc);
    };
    return KeyDidResolver;
}(DidResolver));
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
    UniversalDidResolver.prototype.resolve = function (did) {
        return this.resolveDidDocumet(did);
    };
    return UniversalDidResolver;
}(DidResolver));
exports.combinedDidResolver = new CombinedDidResolver('all')
    .addResolver(new EthrDidResolver('eth'))
    .addResolver(new KeyDidResolver('key'))
    .addResolver(new UniversalDidResolver('uniresolver'));
//# sourceMappingURL=resolvers.js.map