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
var crypto_1 = require("crypto");
var elliptic_1 = require("elliptic");
var base58 = __importStar(require("bs58"));
var base64url_1 = __importDefault(require("base64url"));
var globals_1 = require("./globals");
var NodeRSA = require('node-rsa');
var axios = require('axios').default;
exports.ERRORS = Object.freeze({
    INVALID_KEY_FORMAT: 'Invalid key format error',
    NO_PRIVATE_KEY: 'Not a private key',
    INVALID_KEY: 'Invalid key',
    INVALID_KEY_SET: 'Invalid key in set',
    NO_MATCHING_KEY: 'Matching key cannot be found in key set',
    URI_ERROR: 'Cannot resolve jwks from uri',
    KEY_EXISTS: 'Key already exists in the set',
});
var Key = /** @class */ (function () {
    function Key(kid, kty, use, alg) {
        this.kid = kid;
        this.kty = globals_1.KTYS[kty];
        this.use = use;
        this.alg = alg ? alg : '';
        this.private = false;
    }
    Key.prototype.isPrivate = function () {
        return this.private;
    };
    Key.prototype.checkKid = function (kid) {
        return this.kid === kid;
    };
    return Key;
}());
exports.Key = Key;
var RSAKey = /** @class */ (function (_super) {
    __extends(RSAKey, _super);
    function RSAKey(kid, kty, n, e, use, alg) {
        var _this = _super.call(this, kid, kty, use, alg) || this;
        _this.n = n;
        _this.e = e;
        return _this;
    }
    RSAKey.fromPublicKey = function (keyInput) {
        if ('key' in keyInput) {
            var rsaKey = new NodeRSA();
            var format = keyInput.key.indexOf('-----BEGIN RSA PUBLIC KEY-----') > -1 ? 'pkcs1-public-pem' : 'pkcs8-public-pem';
            rsaKey.importKey(keyInput.key, format);
            var n = base64url_1.default.encode(rsaKey.keyPair.n.toBuffer().slice(1));
            var e = rsaKey.keyPair.e.toString(16);
            e = (e % 2 === 0) ? e : '0' + e;
            e = Buffer.from(e, 'hex').toString('base64');
            return new RSAKey(keyInput.kid, globals_1.KTYS.RSA, n, e, keyInput.use, keyInput.alg);
        }
        else {
            return new RSAKey(keyInput.kid, globals_1.KTYS.RSA, keyInput.n, keyInput.e, keyInput.use, keyInput.alg);
        }
    };
    RSAKey.fromPrivateKey = function (keyInput) {
        if ('key' in keyInput) {
            var rsaKey = new NodeRSA();
            var format = keyInput.key.indexOf('-----BEGIN RSA PRIVATE KEY-----') > -1 ? 'pkcs1-private-pem' : 'pkcs8-private-pem';
            rsaKey.importKey(keyInput.key, format);
            var n = base64url_1.default.encode(rsaKey.keyPair.n.toBuffer().slice(1));
            var e = rsaKey.keyPair.e.toString(16);
            e = (e % 2 === 0) ? e : '0' + e;
            e = Buffer.from(e, 'hex').toString('base64');
            var rs256Key = new RSAKey(keyInput.kid, globals_1.KTYS.RSA, n, e, keyInput.use, keyInput.alg);
            rs256Key.private = true;
            rs256Key.p = base64url_1.default.encode(rsaKey.keyPair.p.toBuffer().slice(1));
            rs256Key.q = base64url_1.default.encode(rsaKey.keyPair.q.toBuffer().slice(1));
            rs256Key.d = base64url_1.default.encode(rsaKey.keyPair.d.toBuffer());
            rs256Key.qi = base64url_1.default.encode(rsaKey.keyPair.coeff.toBuffer());
            rs256Key.dp = base64url_1.default.encode(rsaKey.keyPair.dmp1.toBuffer());
            rs256Key.dq = base64url_1.default.encode(rsaKey.keyPair.dmq1.toBuffer());
            return rs256Key;
        }
        else {
            var rs256Key = new RSAKey(keyInput.kid, globals_1.KTYS.RSA, keyInput.n, keyInput.e, keyInput.use, keyInput.alg);
            rs256Key.private = true;
            rs256Key.p = keyInput.p;
            rs256Key.q = keyInput.q;
            rs256Key.d = keyInput.d;
            rs256Key.qi = keyInput.qi;
            rs256Key.dp = keyInput.dp;
            rs256Key.dq = keyInput.dq;
            return rs256Key;
        }
    };
    RSAKey.fromKey = function (keyInput) {
        if (this.isPrivateKeyInput(keyInput))
            return this.fromPrivateKey(keyInput);
        return this.fromPublicKey(keyInput);
    };
    RSAKey.isPrivateKeyInput = function (keyInput) {
        if ('key' in keyInput) {
            return keyInput.isPrivate;
        }
        else {
            var privateKeyObject = keyInput;
            if (privateKeyObject.d &&
                privateKeyObject.dp &&
                privateKeyObject.dq &&
                privateKeyObject.e &&
                privateKeyObject.n &&
                privateKeyObject.p &&
                privateKeyObject.q &&
                privateKeyObject.qi) {
                return true;
            }
            var publicKeyObject = keyInput;
            if (publicKeyObject.e &&
                publicKeyObject.n) {
                return false;
            }
            throw new Error(exports.ERRORS.INVALID_KEY);
        }
    };
    RSAKey.prototype.toJWK = function (privateKey) {
        if (privateKey) {
            if (this.private) {
                return {
                    kty: this.kty,
                    use: this.use,
                    kid: this.kid,
                    alg: this.alg,
                    p: this.p,
                    q: this.q,
                    d: this.d,
                    e: this.e,
                    qi: this.qi,
                    dp: this.dp,
                    dq: this.dq,
                    n: this.n,
                };
            }
            else {
                throw new Error(exports.ERRORS.NO_PRIVATE_KEY);
            }
        }
        else {
            return {
                kty: this.kty,
                use: this.use,
                kid: this.kid,
                alg: this.alg,
                e: this.e,
                n: this.n,
            };
        }
    };
    RSAKey.prototype.toPEM = function (format) {
        if (format === void 0) { format = 'pkcs8'; }
        var rsaKey = new NodeRSA();
        var exportFormat;
        if (this.private) {
            exportFormat = format + '-private-pem';
            rsaKey.importKey({
                n: base64url_1.default.toBuffer(this.n || ' '),
                e: base64url_1.default.toBuffer(this.e || ' '),
                p: base64url_1.default.toBuffer(this.p || ' '),
                q: base64url_1.default.toBuffer(this.q || ' '),
                d: base64url_1.default.toBuffer(this.d || ' '),
                coeff: base64url_1.default.toBuffer(this.qi || ' '),
                dmp1: base64url_1.default.toBuffer(this.dp || ' '),
                dmq1: base64url_1.default.toBuffer(this.dq || ' '),
            }, 'components');
        }
        else {
            exportFormat = format + '-public-pem';
            rsaKey.importKey({
                n: base64url_1.default.toBuffer(this.n || ' '),
                e: base64url_1.default.toBuffer(this.e || ' '),
            }, 'components-public');
        }
        return rsaKey.exportKey(exportFormat);
    };
    RSAKey.prototype.exportKey = function (format) {
        switch (format) {
            case globals_1.KEY_FORMATS.PKCS1_PEM: return this.toPEM('pkcs1');
            case globals_1.KEY_FORMATS.PKCS8_PEM: return this.toPEM('pkcs8');
            case globals_1.KEY_FORMATS.HEX:
            case globals_1.KEY_FORMATS.BASE58:
            case globals_1.KEY_FORMATS.BASE64:
            case globals_1.KEY_FORMATS.BASE64URL:
            default: throw new Error(exports.ERRORS.INVALID_KEY_FORMAT);
        }
    };
    RSAKey.prototype.getMinimalJWK = function (privateKey) {
        if (privateKey) {
            if (this.isPrivate()) {
                return {
                    d: this.d,
                    dp: this.dp,
                    dq: this.dq,
                    e: this.e,
                    kty: this.kty,
                    n: this.n,
                    p: this.p,
                    q: this.q,
                    qi: this.qi,
                };
            }
            else {
                throw new Error(exports.ERRORS.NO_PRIVATE_KEY);
            }
        }
        else {
            return {
                e: this.e,
                kty: this.kty,
                n: this.n,
            };
        }
    };
    return RSAKey;
}(Key));
exports.RSAKey = RSAKey;
var ECKey = /** @class */ (function (_super) {
    __extends(ECKey, _super);
    function ECKey(kid, kty, crv, x, y, use, alg) {
        var _this = _super.call(this, kid, kty, use, alg) || this;
        _this.crv = crv;
        _this.x = x;
        _this.y = y;
        return _this;
    }
    ECKey.fromPublicKey = function (keyInput) {
        if ('key' in keyInput) {
            var key_buffer = Buffer.alloc(1);
            try {
                switch (keyInput.format) {
                    case globals_1.KEY_FORMATS.BASE58:
                        key_buffer = base58.decode(keyInput.key);
                        break;
                    case globals_1.KEY_FORMATS.BASE64:
                        key_buffer = base64url_1.default.toBuffer(base64url_1.default.fromBase64(keyInput.key));
                        break;
                    case globals_1.KEY_FORMATS.HEX:
                        key_buffer = Buffer.from(keyInput.key, 'hex');
                        break;
                    default: throw new Error(exports.ERRORS.INVALID_KEY_FORMAT);
                }
            }
            catch (err) {
                throw new Error(exports.ERRORS.INVALID_KEY_FORMAT);
            }
            var ec = new elliptic_1.ec('secp256k1');
            var ellipticKey = void 0;
            ellipticKey = ec.keyFromPublic(key_buffer);
            var x = base64url_1.default.encode(ellipticKey.getPublic().getX().toArrayLike(Buffer));
            var y = base64url_1.default.encode(ellipticKey.getPublic().getY().toArrayLike(Buffer));
            return new ECKey(keyInput.kid, globals_1.KTYS.EC, 'secp256k1', x, y, keyInput.use, keyInput.alg);
        }
        else {
            return new ECKey(keyInput.kid, globals_1.KTYS.EC, keyInput.crv, keyInput.x, keyInput.y, keyInput.use, keyInput.alg);
        }
    };
    ECKey.fromPrivateKey = function (keyInput) {
        if ('key' in keyInput) {
            var key_buffer = Buffer.alloc(1);
            try {
                switch (keyInput.format) {
                    case globals_1.KEY_FORMATS.BASE58:
                        key_buffer = base58.decode(keyInput.key);
                        break;
                    case globals_1.KEY_FORMATS.BASE64:
                        key_buffer = base64url_1.default.toBuffer(base64url_1.default.fromBase64(keyInput.key));
                        break;
                    case globals_1.KEY_FORMATS.HEX:
                        key_buffer = Buffer.from(keyInput.key, 'hex');
                        break;
                    default: throw new Error(exports.ERRORS.INVALID_KEY_FORMAT);
                }
            }
            catch (err) {
                throw new Error(exports.ERRORS.INVALID_KEY_FORMAT);
            }
            var ec = new elliptic_1.ec('secp256k1');
            var ellipticKey = void 0;
            ellipticKey = ec.keyFromPrivate(key_buffer);
            var x = base64url_1.default.encode(ellipticKey.getPublic().getX().toArrayLike(Buffer));
            var y = base64url_1.default.encode(ellipticKey.getPublic().getY().toArrayLike(Buffer));
            var ecKey = new ECKey(keyInput.kid, globals_1.KTYS.EC, 'secp256k1', x, y, keyInput.use, keyInput.alg);
            ecKey.d = base64url_1.default.encode(ellipticKey.getPrivate().toArrayLike(Buffer));
            ecKey.private = true;
            return ecKey;
        }
        else {
            var ecKey = new ECKey(keyInput.kid, globals_1.KTYS.EC, keyInput.crv, keyInput.x, keyInput.y, keyInput.use, keyInput.alg);
            ecKey.private = true;
            ecKey.d = keyInput.d;
            return ecKey;
        }
    };
    ECKey.fromKey = function (keyInput) {
        if (this.isPrivateKeyInput(keyInput))
            return this.fromPrivateKey(keyInput);
        return this.fromPublicKey(keyInput);
    };
    ECKey.isPrivateKeyInput = function (keyInput) {
        if ('key' in keyInput) {
            return keyInput.isPrivate;
        }
        else {
            var privateKeyObject = keyInput;
            if (privateKeyObject.d &&
                privateKeyObject.x &&
                privateKeyObject.y) {
                return true;
            }
            var publicKeyObject = keyInput;
            if (publicKeyObject.x &&
                publicKeyObject.y) {
                return false;
            }
            throw new Error(exports.ERRORS.INVALID_KEY);
        }
    };
    ECKey.prototype.toJWK = function (privateKey) {
        if (privateKey) {
            if (this.private) {
                return {
                    kty: this.kty,
                    use: this.use,
                    kid: this.kid,
                    alg: this.alg,
                    crv: this.crv,
                    x: this.x,
                    y: this.y,
                    d: this.d,
                };
            }
            else {
                throw new Error(exports.ERRORS.NO_PRIVATE_KEY);
            }
        }
        else {
            return {
                kty: this.kty,
                use: this.use,
                kid: this.kid,
                alg: this.alg,
                crv: this.crv,
                x: this.x,
                y: this.y,
            };
        }
    };
    ECKey.prototype.exportKey = function (format) {
        var ec = new elliptic_1.ec('secp256k1');
        var keyString;
        if (this.private) {
            keyString = ec.keyFromPrivate(base64url_1.default.toBuffer(this.d || ' ')).getPrivate().toArrayLike(Buffer);
        }
        else {
            var pub = {
                x: base64url_1.default.decode(this.x, 'hex'),
                y: base64url_1.default.decode(this.y, 'hex')
            };
            keyString = Buffer.from(ec.keyFromPublic(pub).getPublic().encode('hex', false), 'hex');
        }
        switch (format) {
            case globals_1.KEY_FORMATS.HEX: return keyString.toString('hex');
            case globals_1.KEY_FORMATS.BASE58: return base58.encode(keyString);
            case globals_1.KEY_FORMATS.BASE64: return keyString.toString('base64');
            case globals_1.KEY_FORMATS.BASE64URL: return base64url_1.default.encode(keyString);
            case globals_1.KEY_FORMATS.PKCS1_PEM:
            case globals_1.KEY_FORMATS.PKCS8_PEM:
            default: throw new Error(exports.ERRORS.INVALID_KEY_FORMAT);
        }
    };
    ECKey.prototype.getMinimalJWK = function (privateKey) {
        if (privateKey) {
            if (this.isPrivate()) {
                return {
                    crv: this.crv,
                    d: this.d,
                    kty: this.kty,
                    x: this.x,
                    y: this.y,
                };
            }
            else {
                throw new Error(exports.ERRORS.NO_PRIVATE_KEY);
            }
        }
        else {
            return {
                crv: this.crv,
                kty: this.kty,
                x: this.x,
                y: this.y,
            };
        }
    };
    return ECKey;
}(Key));
exports.ECKey = ECKey;
var OKP = /** @class */ (function (_super) {
    __extends(OKP, _super);
    function OKP(kid, kty, crv, x, use, alg) {
        var _this = _super.call(this, kid, kty, use, alg) || this;
        _this.crv = crv;
        _this.x = x;
        return _this;
    }
    OKP.fromPublicKey = function (keyInput) {
        if ('key' in keyInput) {
            var key_buffer = Buffer.alloc(1);
            try {
                switch (keyInput.format) {
                    case globals_1.KEY_FORMATS.BASE58:
                        key_buffer = base58.decode(keyInput.key);
                        break;
                    case globals_1.KEY_FORMATS.BASE64:
                        key_buffer = base64url_1.default.toBuffer(base64url_1.default.fromBase64(keyInput.key));
                        break;
                    case globals_1.KEY_FORMATS.HEX:
                        key_buffer = Buffer.from(keyInput.key, 'hex');
                        break;
                    default: throw new Error(exports.ERRORS.INVALID_KEY_FORMAT);
                }
            }
            catch (err) {
                throw new Error(exports.ERRORS.INVALID_KEY_FORMAT);
            }
            var ed = new elliptic_1.eddsa('ed25519');
            var ellipticKey = void 0;
            ellipticKey = ed.keyFromPublic(key_buffer);
            var x = base64url_1.default.encode(ellipticKey.getPublic());
            return new OKP(keyInput.kid, globals_1.KTYS.OKP, 'Ed25519', x, keyInput.use, keyInput.alg);
        }
        else {
            return new OKP(keyInput.kid, globals_1.KTYS.OKP, keyInput.crv, keyInput.x, keyInput.use, keyInput.alg);
        }
    };
    OKP.fromPrivateKey = function (keyInput) {
        if ('key' in keyInput) {
            var key_buffer = Buffer.alloc(1);
            try {
                switch (keyInput.format) {
                    case globals_1.KEY_FORMATS.BASE58:
                        key_buffer = base58.decode(keyInput.key);
                        break;
                    case globals_1.KEY_FORMATS.BASE64:
                        key_buffer = base64url_1.default.toBuffer(base64url_1.default.fromBase64(keyInput.key));
                        break;
                    case globals_1.KEY_FORMATS.HEX:
                        key_buffer = Buffer.from(keyInput.key, 'hex');
                        break;
                    default: throw new Error(exports.ERRORS.INVALID_KEY_FORMAT);
                }
            }
            catch (err) {
                throw new Error(exports.ERRORS.INVALID_KEY_FORMAT);
            }
            var ed = new elliptic_1.eddsa('ed25519');
            var ellipticKey = void 0;
            ellipticKey = ed.keyFromSecret(key_buffer);
            var x = base64url_1.default.encode(ellipticKey.getPublic());
            var ecKey = new OKP(keyInput.kid, globals_1.KTYS.OKP, 'Ed25519', x, keyInput.use, keyInput.alg);
            ecKey.d = base64url_1.default.encode(ellipticKey.getSecret());
            ecKey.private = true;
            return ecKey;
        }
        else {
            var ecKey = new OKP(keyInput.kid, globals_1.KTYS.OKP, keyInput.crv, keyInput.x, keyInput.use, keyInput.alg);
            ecKey.private = true;
            ecKey.d = keyInput.d;
            return ecKey;
        }
    };
    OKP.fromKey = function (keyInput) {
        if (this.isPrivateKeyInput(keyInput))
            return this.fromPrivateKey(keyInput);
        return this.fromPublicKey(keyInput);
    };
    OKP.isPrivateKeyInput = function (keyInput) {
        if ('key' in keyInput) {
            return keyInput.isPrivate;
        }
        else {
            var privateKeyObject = keyInput;
            if (privateKeyObject.d &&
                privateKeyObject.x) {
                return true;
            }
            var publicKeyObject = keyInput;
            if (publicKeyObject.x) {
                return false;
            }
            throw new Error(exports.ERRORS.INVALID_KEY);
        }
    };
    OKP.prototype.toJWK = function (privateKey) {
        if (privateKey) {
            if (this.private) {
                return {
                    kty: this.kty,
                    use: this.use,
                    kid: this.kid,
                    alg: this.alg,
                    crv: this.crv,
                    x: this.x,
                    d: this.d,
                };
            }
            else {
                throw new Error(exports.ERRORS.NO_PRIVATE_KEY);
            }
        }
        else {
            return {
                kty: this.kty,
                use: this.use,
                kid: this.kid,
                alg: this.alg,
                crv: this.crv,
                x: this.x,
            };
        }
    };
    OKP.prototype.exportKey = function (format) {
        var ed = new elliptic_1.eddsa('ed25519');
        var keyString;
        if (this.private) {
            keyString = ed.keyFromSecret(base64url_1.default.toBuffer(this.d || ' ')).getSecret();
        }
        else {
            keyString = ed.keyFromPublic(base64url_1.default.toBuffer(this.x)).getPublic();
        }
        switch (format) {
            case globals_1.KEY_FORMATS.HEX: return keyString.toString('hex');
            case globals_1.KEY_FORMATS.BASE58: return base58.encode(keyString);
            case globals_1.KEY_FORMATS.BASE64: return keyString.toString('base64');
            case globals_1.KEY_FORMATS.BASE64URL: return base64url_1.default.encode(keyString);
            case globals_1.KEY_FORMATS.PKCS1_PEM:
            case globals_1.KEY_FORMATS.PKCS8_PEM:
            default: throw new Error(exports.ERRORS.INVALID_KEY_FORMAT);
        }
    };
    OKP.prototype.getMinimalJWK = function (privateKey) {
        if (privateKey) {
            if (this.isPrivate()) {
                return {
                    crv: this.crv,
                    d: this.d,
                    kty: this.kty,
                    x: this.x,
                };
            }
            else {
                throw new Error(exports.ERRORS.NO_PRIVATE_KEY);
            }
        }
        else {
            return {
                crv: this.crv,
                kty: this.kty,
                x: this.x,
            };
        }
    };
    return OKP;
}(Key));
exports.OKP = OKP;
var KeySet = /** @class */ (function () {
    function KeySet() {
        this.ketSet = [];
        this.uri = '';
    }
    KeySet.prototype.setKeys = function (keySet) {
        var newKeySet = [];
        keySet.forEach(function (key) {
            switch (key.kty) {
                case globals_1.KTYS[globals_1.KTYS.RSA]: {
                    newKeySet.push(RSAKey.fromKey(key));
                    break;
                }
                case globals_1.KTYS[globals_1.KTYS.EC]: {
                    newKeySet.push(ECKey.fromKey(key));
                    break;
                }
                case globals_1.KTYS[globals_1.KTYS.OKP]: {
                    newKeySet.push(OKP.fromKey(key));
                    break;
                }
                default: throw new Error(exports.ERRORS.INVALID_KEY_SET);
            }
        });
        this.ketSet = newKeySet;
    };
    KeySet.prototype.setURI = function (uri) {
        return __awaiter(this, void 0, void 0, function () {
            var returnedSet, err_1;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        this.uri = uri;
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 3, , 4]);
                        return [4 /*yield*/, axios.get(this.uri)];
                    case 2:
                        returnedSet = _a.sent();
                        this.setKeys(returnedSet.data.keys);
                        return [3 /*break*/, 4];
                    case 3:
                        err_1 = _a.sent();
                        throw new Error(exports.ERRORS.URI_ERROR);
                    case 4: return [2 /*return*/];
                }
            });
        });
    };
    KeySet.prototype.getKey = function (kid) {
        var keys = this.ketSet.filter(function (k) { return k.checkKid(kid); });
        if (keys.length > 0)
            return keys;
        throw new Error(exports.ERRORS.NO_MATCHING_KEY);
    };
    KeySet.prototype.addKey = function (key) {
        if (this.ketSet.filter(function (k) { return k.checkKid(key.kid); }).length === 0) {
            switch (key.kty) {
                case globals_1.KTYS[globals_1.KTYS.RSA]: {
                    this.ketSet.push(RSAKey.fromKey(key));
                    break;
                }
                case globals_1.KTYS[globals_1.KTYS.EC]: {
                    this.ketSet.push(ECKey.fromKey(key));
                    break;
                }
                case globals_1.KTYS[globals_1.KTYS.OKP]: {
                    this.ketSet.push(OKP.fromKey(key));
                    break;
                }
                default: throw new Error(exports.ERRORS.INVALID_KEY_SET);
            }
        }
        else {
            throw new Error(exports.ERRORS.KEY_EXISTS);
        }
    };
    KeySet.prototype.removeKey = function (kid) {
        this.ketSet = this.ketSet.filter(function (key) { return !key.checkKid(kid); });
    };
    KeySet.prototype.size = function () {
        return this.ketSet.length;
    };
    return KeySet;
}());
exports.KeySet = KeySet;
function calculateThumbprint(minimalJWK) {
    var sha256 = crypto_1.createHash('sha256');
    var hash = sha256.update(JSON.stringify(minimalJWK)).digest();
    return base64url_1.default.encode(hash);
}
exports.calculateThumbprint = calculateThumbprint;
//# sourceMappingURL=JWKUtils.js.map