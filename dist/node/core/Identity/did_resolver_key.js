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
Object.defineProperty(exports, "__esModule", { value: true });
var did_resolver_base_1 = require("./did_resolver_base");
var globals_1 = require("../globals");
// const {Ed25519VerificationKey2018} = require( '@digitalbazaar/ed25519-verification-key-2018');
// const didKeyDriver = require('@digitalbazaar/did-method-key').driver({verificationSuite: Ed25519VerificationKey2018});
/**
 * @classdesc Resolver class for did:key
 * @extends {DidResolver}
 */
var KeyDidResolver2 = /** @class */ (function (_super) {
    __extends(KeyDidResolver2, _super);
    function KeyDidResolver2() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    KeyDidResolver2.prototype.resolveDidDocumet = function (did, crypto_suite) {
        return __awaiter(this, void 0, void 0, function () {
            var didKeyDriver, didDocument, err_1;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (crypto_suite === undefined)
                            crypto_suite = globals_1.CRYPTO_SUITES.Ed25519VerificationKey2020;
                        didKeyDriver = this.getDidDriverForCryptoSuite(crypto_suite);
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 3, , 4]);
                        return [4 /*yield*/, didKeyDriver.get({ did: did })];
                    case 2:
                        didDocument = _a.sent();
                        return [2 /*return*/, didDocument];
                    case 3:
                        err_1 = _a.sent();
                        return [2 /*return*/, undefined];
                    case 4: return [2 /*return*/];
                }
            });
        });
    };
    KeyDidResolver2.prototype.getDidDriverForCryptoSuite = function (crypto_suite_package) {
        var didKeyDriver;
        switch (crypto_suite_package) {
            case globals_1.CRYPTO_SUITES.Ed25519VerificationKey2018:
                var Ed25519VerificationKey2018 = require(globals_1.CRYPTO_SUITES.Ed25519VerificationKey2018).Ed25519VerificationKey2018;
                didKeyDriver = require('@digitalbazaar/did-method-key').driver({ verificationSuite: Ed25519VerificationKey2018 });
                break;
            default:
                var Ed25519VerificationKey2020 = require(globals_1.CRYPTO_SUITES.Ed25519VerificationKey2020).Ed25519VerificationKey2020;
                didKeyDriver = require('@digitalbazaar/did-method-key').driver({ verificationSuite: Ed25519VerificationKey2020 });
                break;
        }
        return didKeyDriver;
    };
    return KeyDidResolver2;
}(did_resolver_base_1.DidResolver));
exports.KeyDidResolver2 = KeyDidResolver2;
//# sourceMappingURL=did_resolver_key.js.map