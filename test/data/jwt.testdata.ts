import { RSAKey, ECKey, OKP } from "../../src/core/jwk-utils";
import { ALGORITHMS } from "../../src/core/globals";
import { TD_KEY_PAIRS, TD_KEY_PAIRS_INVALID } from "./key-pairs.testdata";

const rs256TestResource = {
  jwtDecoded: {
    header: {
      alg: ALGORITHMS[ALGORITHMS.RS256],
      typ: "JWT",
      kid: "key_1",
    },
    payload: {
      sub: "1234567890",
      name: "John Doe",
      admin: true,
    },
  },
  privateKey: RSAKey.fromPrivateKey(TD_KEY_PAIRS.rsa_4.privateKey),
  publicKey: RSAKey.fromPublicKey(TD_KEY_PAIRS.rsa_4.publicKey),
  publicKeyWrong: RSAKey.fromPublicKey(TD_KEY_PAIRS_INVALID.rsa_4.publicKey),
};

const es256kTestResource = {
  jwtDecoded: {
    header: {
      alg: ALGORITHMS[ALGORITHMS.ES256K],
      typ: "JWT",
      kid: "key_1",
    },
    payload: {
      sub: "1234567890",
      name: "John Doe",
      admin: true,
    },
  },
  privateKey: ECKey.fromPrivateKey(TD_KEY_PAIRS.es256k_1.privateKey),
  publicKey: ECKey.fromPublicKey(TD_KEY_PAIRS.es256k_1.publicKey),
  publicKeyWrong: ECKey.fromPublicKey(TD_KEY_PAIRS_INVALID.es256k_1.publicKey),
};

const es256kRecoverableResources = {
  jwtDecoded: {
    header: {
      alg: ALGORITHMS[ALGORITHMS["ES256K-R"]],
      typ: "JWT",
      kid: "key_1",
    },
    payload: {
      sub: "1234567890",
      name: "John Doe",
      admin: true,
    },
  },
  privateKey: TD_KEY_PAIRS.es256kr_1.privateKey,
  publicKey: TD_KEY_PAIRS.es256kr_1.publicKey,
  publicKeyWrong: TD_KEY_PAIRS_INVALID.es256kr_1.publicKey,
};

const edDsaTestResources = {
  jwtDecoded: {
    header: {
      alg: ALGORITHMS[ALGORITHMS.EdDSA],
      typ: "JWT",
      kid: "key_1",
    },
    payload: {
      sub: "1234567890",
      name: "John Doe",
      admin: true,
    },
  },
  privateKey: OKP.fromPrivateKey(TD_KEY_PAIRS.okp_4.privateKey),
  publicKey: OKP.fromPublicKey(TD_KEY_PAIRS.okp_4.publicKey),
  publicKeyWrong: OKP.fromPublicKey(TD_KEY_PAIRS_INVALID.okp_4.publicKey),
};

export {
  rs256TestResource,
  es256kTestResource,
  es256kRecoverableResources,
  edDsaTestResources,
};
