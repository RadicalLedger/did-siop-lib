import { ALGORITHMS, KEY_FORMATS } from "./../src/core/globals";
import { sign, verify } from "../src/core/jwt";
import {
  rs256TestResource,
  es256kTestResource,
  es256kRecoverableResources,
  edDsaTestResources,
} from "./data/jwt.testdata";

describe("JWT functions", function () {
  test("JWT signing and verification RS256", async () => {
    let jwt = sign(rs256TestResource.jwtDecoded, {
      key: rs256TestResource.privateKey.exportKey(KEY_FORMATS.PKCS8_PEM),
      kid: rs256TestResource.jwtDecoded.header.kid,
      alg: ALGORITHMS.RS256,
      format: KEY_FORMATS.PKCS8_PEM,
    });
    let validity = verify(jwt, {
      key: rs256TestResource.publicKey.exportKey(KEY_FORMATS.PKCS1_PEM),
      kid: rs256TestResource.jwtDecoded.header.kid,
      alg: ALGORITHMS.RS256,
      format: KEY_FORMATS.PKCS1_PEM,
    });
    expect(validity).toBeTruthy();
    validity = verify(jwt, {
      key: rs256TestResource.publicKeyWrong.exportKey(KEY_FORMATS.PKCS1_PEM),
      kid: rs256TestResource.jwtDecoded.header.kid,
      alg: ALGORITHMS.RS256,
      format: KEY_FORMATS.PKCS1_PEM,
    });
    expect(validity).toBeFalsy();
  });
  test("JWT signing and verification ES256K", async () => {
    let signing: any = {
      key: es256kTestResource.privateKey.exportKey(KEY_FORMATS.HEX),
      kid: es256kTestResource.jwtDecoded.header.kid,
      alg: ALGORITHMS.ES256K,
      format: KEY_FORMATS.HEX,
    };

    let jwt = sign(es256kTestResource.jwtDecoded, signing);
    let validity = verify(jwt, {
      key: es256kTestResource.publicKey.exportKey(KEY_FORMATS.HEX),
      kid: es256kTestResource.jwtDecoded.header.kid,
      alg: ALGORITHMS.ES256K,
      format: KEY_FORMATS.HEX,
    });
    expect(validity).toBeTruthy();
    validity = verify(jwt, {
      key: es256kTestResource.publicKeyWrong.exportKey(KEY_FORMATS.HEX),
      kid: es256kTestResource.jwtDecoded.header.kid,
      alg: ALGORITHMS.ES256K,
      format: KEY_FORMATS.HEX,
    });
    expect(validity).toBeFalsy();
  }),
    test("JWT signing and verification ES256K-R", async () => {
      let jwt = sign(es256kRecoverableResources.jwtDecoded, {
        key: es256kRecoverableResources.privateKey,
        kid: es256kRecoverableResources.jwtDecoded.header.kid,
        alg: ALGORITHMS["ES256K-R"],
        format: KEY_FORMATS.HEX,
      });
      let validity = verify(jwt, {
        key: es256kRecoverableResources.publicKey,
        kid: es256kRecoverableResources.jwtDecoded.header.kid,
        alg: ALGORITHMS["ES256K-R"],
        format: KEY_FORMATS.HEX,
      });
      expect(validity).toBeTruthy();
      validity = verify(jwt, {
        key: es256kRecoverableResources.publicKeyWrong,
        kid: es256kRecoverableResources.jwtDecoded.header.kid,
        alg: ALGORITHMS["ES256K-R"],
        format: KEY_FORMATS.HEX,
      });
      expect(validity).toBeFalsy();
    });
  test("JWT signing and verification EdDSA", async () => {
    let jwt = sign(edDsaTestResources.jwtDecoded, {
      key: edDsaTestResources.privateKey.exportKey(KEY_FORMATS.HEX),
      kid: edDsaTestResources.jwtDecoded.header.kid,
      alg: ALGORITHMS.EdDSA,
      format: KEY_FORMATS.HEX,
    });
    let validity = verify(jwt, {
      key: edDsaTestResources.publicKey.exportKey(KEY_FORMATS.HEX),
      kid: edDsaTestResources.jwtDecoded.header.kid,
      alg: ALGORITHMS.EdDSA,
      format: KEY_FORMATS.HEX,
    });
    expect(validity).toBeTruthy();
    validity = verify(jwt, {
      key: edDsaTestResources.publicKeyWrong.exportKey(KEY_FORMATS.HEX),
      kid: edDsaTestResources.jwtDecoded.header.kid,
      alg: ALGORITHMS.EdDSA,
      format: KEY_FORMATS.HEX,
    });
    expect(validity).toBeFalsy();
  });
});
