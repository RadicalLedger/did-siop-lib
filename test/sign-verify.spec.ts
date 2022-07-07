import {
  RSASigner,
  ECSigner,
  ES256KRecoverableSigner,
  OKPSigner,
} from "../src/core/signers";
import { KeyObjects, RSAKey, ECKey, OKP } from "../src/core/jwk-utils";
import { ALGORITHMS } from "../src/core/globals";
import {
  RSAVerifier,
  ECVerifier,
  ES256KRecoverableVerifier,
  OKPVerifier,
} from "../src/core/verifiers";

import { TD_KEY_PAIRS, TD_KEY_PAIRS_INVALID } from "./data/key-pairs.testdata";

describe("Signing and verifying with VALID keys", function () {
  test("RSA sign/verify", async () => {
    let publicJWK: KeyObjects.RSAPublicKeyObject = TD_KEY_PAIRS.rsa_1.publicJWK;
    let privateJWK: KeyObjects.RSAPrivateKeyObject =
      TD_KEY_PAIRS.rsa_1.privateJWK;

    let privateKey = RSAKey.fromKey(privateJWK);
    let publicKey = RSAKey.fromKey(publicJWK);

    let message = "RSA test message";

    let signature = new RSASigner().sign(message, privateKey, ALGORITHMS.RS256);
    let validity = new RSAVerifier().verify(
      message,
      Buffer.from(signature),
      publicKey,
      ALGORITHMS.RS256
    );
    expect(validity).toBeTruthy();
  });
  test("EC sign/verify", async () => {
    let publicJWK: KeyObjects.ECPublicKeyObject = TD_KEY_PAIRS.ec_1.publicJWK;
    let privateJWK: KeyObjects.ECPrivateKeyObject =
      TD_KEY_PAIRS.ec_1.privateJWK;

    let privateKey = ECKey.fromKey(privateJWK);
    let publicKey = ECKey.fromKey(publicJWK);

    let message = "EC test message";

    let signature = new ECSigner().sign(message, privateKey, ALGORITHMS.ES256K);
    let validity = new ECVerifier().verify(
      message,
      signature,
      publicKey,
      ALGORITHMS.ES256K
    );
    expect(validity).toBeTruthy();

    let es256kRPrivateKey = TD_KEY_PAIRS.es256kr_1.privateKey;
    let es256kRPublicKey = TD_KEY_PAIRS.es256kr_1.publicKey;

    signature = new ES256KRecoverableSigner().sign(message, es256kRPrivateKey);
    validity = new ES256KRecoverableVerifier().verify(
      message,
      signature,
      es256kRPublicKey
    );
    expect(validity).toBeTruthy();
  });
  test("OKP sign/verify", async () => {
    let publicJWK: KeyObjects.OKPPublicKeyObject = TD_KEY_PAIRS.okp_1.publicJWK;
    let privateJWK: KeyObjects.OKPPrivateKeyObject =
      TD_KEY_PAIRS.okp_1.privateJWK;

    let privateKey = OKP.fromKey(privateJWK);
    let publicKey = OKP.fromKey(publicJWK);

    let message = "EdDSA test message";

    let signature = new OKPSigner().sign(message, privateKey, ALGORITHMS.EdDSA);
    let validity = new OKPVerifier().verify(
      message,
      signature,
      publicKey,
      ALGORITHMS.EdDSA
    );
    expect(validity).toBeTruthy();
  });
});

describe("Signing and verifying with INVALID keys", function () {
  test("RSA sign/verify", async () => {
    let publicJWK: KeyObjects.RSAPublicKeyObject =
      TD_KEY_PAIRS_INVALID.rsa_1.publicJWK;
    let privateJWK: KeyObjects.RSAPrivateKeyObject =
      TD_KEY_PAIRS_INVALID.rsa_1.privateJWK;

    let privateKey = RSAKey.fromKey(privateJWK);
    let publicKey = RSAKey.fromKey(publicJWK);

    let message = "RSA test message";

    let signature = new RSASigner().sign(message, privateKey, ALGORITHMS.RS256);

    let validity = new RSAVerifier().verify(
      message,
      Buffer.from(signature),
      publicKey,
      ALGORITHMS.RS256
    );
    expect(validity).toBeFalsy();
  });
  test("EC sign/verify", async () => {
    let publicJWK: KeyObjects.ECPublicKeyObject =
      TD_KEY_PAIRS_INVALID.ec_1.publicJWK;
    let privateJWK: KeyObjects.ECPrivateKeyObject =
      TD_KEY_PAIRS_INVALID.ec_1.privateJWK;

    let privateKey = ECKey.fromKey(privateJWK);
    let publicKey = ECKey.fromKey(publicJWK);

    let message = "EC test message";

    let signature = new ECSigner().sign(message, privateKey, ALGORITHMS.ES256K);
    let validity = new ECVerifier().verify(
      message,
      signature,
      publicKey,
      ALGORITHMS.ES256K
    );
    expect(validity).toBeFalsy();

    let es256kRPrivateKey = TD_KEY_PAIRS_INVALID.es256kr_1.privateKey;
    let es256kRPublicKey = TD_KEY_PAIRS_INVALID.es256kr_1.publicKey;

    signature = new ES256KRecoverableSigner().sign(message, es256kRPrivateKey);
    validity = new ES256KRecoverableVerifier().verify(
      message,
      signature,
      es256kRPublicKey
    );
    expect(validity).toBeFalsy();
  });
  test("OKP sign/verify", async () => {
    let publicJWK: KeyObjects.OKPPublicKeyObject =
      TD_KEY_PAIRS_INVALID.okp_1.publicJWK;
    let privateJWK: KeyObjects.OKPPrivateKeyObject =
      TD_KEY_PAIRS_INVALID.okp_1.privateJWK;

    let privateKey = OKP.fromKey(privateJWK);
    let publicKey = OKP.fromKey(publicJWK);

    let message = "EdDSA test message";

    let signature = new OKPSigner().sign(message, privateKey, ALGORITHMS.EdDSA);
    let validity = new OKPVerifier().verify(
      message,
      signature,
      publicKey,
      ALGORITHMS.EdDSA
    );
    expect(validity).toBeFalsy();
  });
});
