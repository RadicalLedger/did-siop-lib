const TD_KEY_PAIRS = {
  rsa_1: {
    publicJWK: {
      kty: "RSA",
      e: "AQAB",
      use: "enc",
      kid: "key_1",
      alg: "RS256",
      n: "hgU7BWR8A_d5Z4boXZaff3KLte8rEZvA5mGRRF_WMEqp2l9K2dkgT-Z27sSAi-uZrkFKRxtclyW2ZCU4uv5jJH9yWcmksxfV-VYpCFiJVPKiAxTFftUNB0jiFsJDAxgfECorJkYn1s9BbNMzbuiNzUvBqTXKS2Q6rFj0lrCR_mZSwZl1zBW5Rh5c2vK8rWkQ7q2T_Q2eT2QOonzmhfTSZDneqyaOKjom9QRbWgnR6vbVb9beUzZ7W5Y_grdIoQ7VZS5SDdEJrGWrquzmsfigvcuWBbGQw5wnN1cJjWTElITN0FTCJpK2KOuQbQnBtOV9T7hUkGKFmhyDqeclBcDopw",
    },
    privateJWK: {
      p: "0riZ2TyPf66nQpV4iuTdHBsVjIqDBeBq17VOhcf2qma1yIhkVKs5xUFUmDHeXHFIJnP6tnlRkxWgQYKJcicFwuoROkZXByN8qxjC5gc_Yt72oV2j_tZti65khLQ9tG6PW31euxniw42ND2rV-hne77uC8QDFVVoDqADwh_nlyTE",
      kty: "RSA",
      q: "otF1yZwtMBLiAWi04UTU9vg_4IDXTpCqGatVyLYoPLAhB5BJ4s41Yfop7bI7AsYP6ZjFQBuC5rjZ6OmItgkFu6Ha5lOPl1C36vr7hC_fqWLkLwL8cNZ8pZ5_RO0XOFtc10Zv5pNZypJjLHgnDjM7oDyV0YqA7dBLoxrcFytP2Vc",
      d: "Om0vVOOAuU37LGoBBUP0FuC-DbvNv-hyCT3B0dgiDX2PXPcsL5rb3llvwhoCnH1Cy1gFZMiF7hLv1-ruN39Ng4zYMlKZLcaXbxLj4pKOlG0Oul8k1m1VN7bLcfaQtlmeuTJZC1-MYLaMJEBS7OgPYc_EBtu_bGyus5I4VzV1AD3Cv0Kjp5lKb_V8GEshFbsCIszkdXyfGH7PF3SwmsHkyiEEKlCyInLtV1kEPV1s8-ekz9UdhL8_Q-BZRT0JzpsRErgrzQgGZEHp0rXeaMRQWlQWJic4kKdWuTYzSNuDTPyIo8YZhCxOWdQP__saHSi3nfqf8wBl6k3CeRkRAlpVYQ",
      e: "AQAB",
      use: "enc",
      kid: "key_1",
      qi: "O8ZQbD3Y4mh-rMIY0tQJFfPbxMeabWB0htpx1Ry9Y3LJR1U4EHxMmVFD9WLFQfie_Qg0RZNCKCj_cKn_pbL4LxthHV9sF8Wg2O7QBL7ajQHVnN1-SDyhKq3hbq58NJ8dT5gttuY3TOFuIb5vkSMjNvlIZC4cGk2YIMewkfspsm8",
      dp: "Co14FurzfL9wXONDYCFJ-WhZ0en12ct9TkQkJIr5DVuLavl5nMveXsSAygZlTlfV9ycDvTOiJC2HEwDIhVDy9unl5vcy0Ia0bZUV3ZMrV3Y2_6nC1rZCUiZvnj2wgWKwBzLmFZScSJLEJ6t__8Bf672GNy-EsluJp1Y0tXqMSWE",
      alg: "RS256",
      dq: "Sr1kGHw8sgi4_nSWM6JpMEWc7O236DS4ILhp1Izpw5IGV3aAtEB8eNFhVd-u_wL0YwLh6R-34zmPrj8lpopVu1_9ICXTkF5ZTuCPfIqNXTAsFviD8ThEV7J-MaG0OwaVg6ytyWZynW69X7h4FSinglLNYzb1IDWxwtmdlnUnXlk",
      n: "hgU7BWR8A_d5Z4boXZaff3KLte8rEZvA5mGRRF_WMEqp2l9K2dkgT-Z27sSAi-uZrkFKRxtclyW2ZCU4uv5jJH9yWcmksxfV-VYpCFiJVPKiAxTFftUNB0jiFsJDAxgfECorJkYn1s9BbNMzbuiNzUvBqTXKS2Q6rFj0lrCR_mZSwZl1zBW5Rh5c2vK8rWkQ7q2T_Q2eT2QOonzmhfTSZDneqyaOKjom9QRbWgnR6vbVb9beUzZ7W5Y_grdIoQ7VZS5SDdEJrGWrquzmsfigvcuWBbGQw5wnN1cJjWTElITN0FTCJpK2KOuQbQnBtOV9T7hUkGKFmhyDqeclBcDopw",
    },
  },
  ec_1: {
    publicJWK: {
      kty: "EC",
      use: "enc",
      crv: "secp256k1",
      kid: "key_1",
      x: "oquPKizfRHuR3YyX6X1Dw22aIoKi1UiVyVx9xA1f-XQ",
      y: "luHPOmJDwPmr_BzTPN2fifkr6GZ-dmjm5TMrjBUvszQ",
      alg: "ES256K",
    },
    privateJWK: {
      kty: "EC",
      d: "bnTMs3lArTEVvYUIyHXWbXOk_0GlDG__CkKaB4e-lm0",
      use: "enc",
      crv: "secp256k1",
      kid: "key_1",
      x: "oquPKizfRHuR3YyX6X1Dw22aIoKi1UiVyVx9xA1f-XQ",
      y: "luHPOmJDwPmr_BzTPN2fifkr6GZ-dmjm5TMrjBUvszQ",
      alg: "ES256K",
    },
  },
  es256kr_1: {
    publicKey: "0xB07Ead9717b44B6cF439c474362b9B0877CBBF83",
    privateKey:
      "CE438802C1F0B6F12BC6E686F372D7D495BC5AA634134B4A7EA4603CB25F0964",
  },
  okp_1: {
    publicJWK: {
      kty: "OKP",
      use: "enc",
      crv: "Ed25519",
      kid: "key_1",
      x: "5_uoVZOQ--9RfCfwZXV6al-jNyyr9fKJRmt56DEQ8LI",
      alg: "EdDSA",
    },
    privateJWK: {
      kty: "OKP",
      d: "5EX3-YZgi5H2T2eLs9ytK0GbFE2Qm4teiAultZxC29U",
      use: "enc",
      crv: "Ed25519",
      kid: "key_1",
      x: "5_uoVZOQ--9RfCfwZXV6al-jNyyr9fKJRmt56DEQ8LI",
      alg: "EdDSA",
    },
  },
};

export { TD_KEY_PAIRS };
