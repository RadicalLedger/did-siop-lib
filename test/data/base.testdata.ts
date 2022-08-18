import { ALGORITHMS, DidDocument, KEY_FORMATS, KTYS } from "../../src";

const didDocs = {
  ethr_1: {
    didDocument: {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld",
      ],
      id: "did:ethr:rinkeby:0x0345dd0c781893a801588a36051e3bdc61f15f0dd51aa716915e763bd2a2f613f6",
      verificationMethod: [
        {
          id: "did:ethr:rinkeby:0x0345dd0c781893a801588a36051e3bdc61f15f0dd51aa716915e763bd2a2f613f6#controller",
          type: "EcdsaSecp256k1RecoveryMethod2020",
          controller:
            "did:ethr:rinkeby:0x0345dd0c781893a801588a36051e3bdc61f15f0dd51aa716915e763bd2a2f613f6",
          blockchainAccountId:
            "0x1471b1ca1E8515b07825a690c9D6CAbBfAa42e49@eip155:4",
        },
        {
          id: "did:ethr:rinkeby:0x0345dd0c781893a801588a36051e3bdc61f15f0dd51aa716915e763bd2a2f613f6#controllerKey",
          type: "EcdsaSecp256k1VerificationKey2019",
          controller:
            "did:ethr:rinkeby:0x0345dd0c781893a801588a36051e3bdc61f15f0dd51aa716915e763bd2a2f613f6",
          publicKeyHex:
            "0345dd0c781893a801588a36051e3bdc61f15f0dd51aa716915e763bd2a2f613f6",
        },
      ],
      authentication: [
        "did:ethr:rinkeby:0x0345dd0c781893a801588a36051e3bdc61f15f0dd51aa716915e763bd2a2f613f6#controller",
        "did:ethr:rinkeby:0x0345dd0c781893a801588a36051e3bdc61f15f0dd51aa716915e763bd2a2f613f6#controllerKey",
      ],
      assertionMethod: [
        "did:ethr:rinkeby:0x0345dd0c781893a801588a36051e3bdc61f15f0dd51aa716915e763bd2a2f613f6#controller",
        "did:ethr:rinkeby:0x0345dd0c781893a801588a36051e3bdc61f15f0dd51aa716915e763bd2a2f613f6#controllerKey",
      ],
    },
    keys: [
      {
        id: "did:ethr:rinkeby:0x02fc5d9954170fb9bd2d1d18bb9ca645828bc3555edf5f501f0b3cd0dfa8cc17e1#owner",
        kty: KTYS.EC,
        alg: ALGORITHMS["ES256K-R"],
        format: KEY_FORMATS.ETHEREUM_ADDRESS,
        publicKey:
          "0x02fc5d9954170fb9bd2d1d18bb9ca645828bc3555edf5f501f0b3cd0dfa8cc17e1",
        privateKey:
          "2d0651990af6802bf1509cafe5784f98ec35932cb57ee2d8ef7ab0f8f43cf83e",
        address: "0x1471b1ca1E8515b07825a690c9D6CAbBfAa42e49",
        identifier:
          "0x0345dd0c781893a801588a36051e3bdc61f15f0dd51aa716915e763bd2a2f613f6",
      },
    ],
  },
  ethr_2: {
    didDocument: {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld",
      ],
      id: "did:ethr:rinkeby:0x02be73dcaa2013a714b6745f54ff8576df151f8226cc3923538bfbfb9a014584fe",
      verificationMethod: [
        {
          id: "did:ethr:rinkeby:0x02be73dcaa2013a714b6745f54ff8576df151f8226cc3923538bfbfb9a014584fe#controller",
          type: "EcdsaSecp256k1RecoveryMethod2020",
          controller:
            "did:ethr:rinkeby:0x02be73dcaa2013a714b6745f54ff8576df151f8226cc3923538bfbfb9a014584fe",
          blockchainAccountId:
            "0xAf425F2104E9450aB070F03dc6097144C169391d@eip155:4",
        },
        {
          id: "did:ethr:rinkeby:0x02be73dcaa2013a714b6745f54ff8576df151f8226cc3923538bfbfb9a014584fe#controllerKey",
          type: "EcdsaSecp256k1VerificationKey2019",
          controller:
            "did:ethr:rinkeby:0x02be73dcaa2013a714b6745f54ff8576df151f8226cc3923538bfbfb9a014584fe",
          publicKeyHex:
            "02be73dcaa2013a714b6745f54ff8576df151f8226cc3923538bfbfb9a014584fe",
        },
      ],
      authentication: [
        "did:ethr:rinkeby:0x02be73dcaa2013a714b6745f54ff8576df151f8226cc3923538bfbfb9a014584fe#controller",
        "did:ethr:rinkeby:0x02be73dcaa2013a714b6745f54ff8576df151f8226cc3923538bfbfb9a014584fe#controllerKey",
      ],
      assertionMethod: [
        "did:ethr:rinkeby:0x02be73dcaa2013a714b6745f54ff8576df151f8226cc3923538bfbfb9a014584fe#controller",
        "did:ethr:rinkeby:0x02be73dcaa2013a714b6745f54ff8576df151f8226cc3923538bfbfb9a014584fe#controllerKey",
      ],
    },
    keys: [
      {
        id: "did:ethr:rinkeby:0x02fc5d9954170fb9bd2d1d18bb9ca645828bc3555edf5f501f0b3cd0dfa8cc17e1#owner",
        kty: KTYS.EC,
        alg: ALGORITHMS["ES256K-R"],
        format: KEY_FORMATS.ETHEREUM_ADDRESS,
        publicKey:
          "0x02fc5d9954170fb9bd2d1d18bb9ca645828bc3555edf5f501f0b3cd0dfa8cc17e1",
        privateKey:
          "c4873e901915343baf7302b0b87bae70bf5726e9280d415b3f7fc85908cc9d5a",
        address: "0xAf425F2104E9450aB070F03dc6097144C169391d",
        identifier:
          "0x02be73dcaa2013a714b6745f54ff8576df151f8226cc3923538bfbfb9a014584fe",
      },
    ],
  },
  key_2018_1: {
    didDocument: {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/ed25519-2018/v1",
        "https://w3id.org/security/suites/x25519-2019/v1",
      ],
      id: "did:key:z6Mkr4zjFPqDsoQPo9t17N7pXo5oQXfjCFJ2bFDqpKnf9rBv",
      verificationMethod: [
        {
          id: "did:key:z6Mkr4zjFPqDsoQPo9t17N7pXo5oQXfjCFJ2bFDqpKnf9rBv#z6Mkr4zjFPqDsoQPo9t17N7pXo5oQXfjCFJ2bFDqpKnf9rBv",
          type: "Ed25519VerificationKey2018",
          controller:
            "did:key:z6Mkr4zjFPqDsoQPo9t17N7pXo5oQXfjCFJ2bFDqpKnf9rBv",
          publicKeyBase58: "Ccjgf9anYFuvgf3JRo9yghXoaxPsnN3fuEJuz3peEdQY",
        },
      ],
      authentication: [
        "did:key:z6Mkr4zjFPqDsoQPo9t17N7pXo5oQXfjCFJ2bFDqpKnf9rBv#z6Mkr4zjFPqDsoQPo9t17N7pXo5oQXfjCFJ2bFDqpKnf9rBv",
      ],
      assertionMethod: [
        "did:key:z6Mkr4zjFPqDsoQPo9t17N7pXo5oQXfjCFJ2bFDqpKnf9rBv#z6Mkr4zjFPqDsoQPo9t17N7pXo5oQXfjCFJ2bFDqpKnf9rBv",
      ],
      capabilityDelegation: [
        "did:key:z6Mkr4zjFPqDsoQPo9t17N7pXo5oQXfjCFJ2bFDqpKnf9rBv#z6Mkr4zjFPqDsoQPo9t17N7pXo5oQXfjCFJ2bFDqpKnf9rBv",
      ],
      capabilityInvocation: [
        "did:key:z6Mkr4zjFPqDsoQPo9t17N7pXo5oQXfjCFJ2bFDqpKnf9rBv#z6Mkr4zjFPqDsoQPo9t17N7pXo5oQXfjCFJ2bFDqpKnf9rBv",
      ],
      keyAgreement: [
        {
          id: "did:key:z6Mkr4zjFPqDsoQPo9t17N7pXo5oQXfjCFJ2bFDqpKnf9rBv#z6LSoGhqMKrk8Zcv6Wq4pwp3tkqeYDqwTTzxnk9oGLyytBDw",
          type: "X25519KeyAgreementKey2019",
          controller:
            "did:key:z6Mkr4zjFPqDsoQPo9t17N7pXo5oQXfjCFJ2bFDqpKnf9rBv",
          publicKeyBase58: "CbXfq23t36uB18TJJJJ6aAdAh5JpkrpoumS7mtLTAoTB",
        },
      ],
    },
    keys: [
      {
        id: "did:key:z6Mkr4zjFPqDsoQPo9t17N7pXo5oQXfjCFJ2bFDqpKnf9rBv#z6Mkr4zjFPqDsoQPo9t17N7pXo5oQXfjCFJ2bFDqpKnf9rBv",
        kty: KTYS.OKP,
        alg: ALGORITHMS.EdDSA,
        format: KEY_FORMATS.BASE58,
        publicKey: "Ccjgf9anYFuvgf3JRo9yghXoaxPsnN3fuEJuz3peEdQY",
        privateKey:
          "3jz6AEkock9fif1dt2VBUtqmMg6JjHYKHdpBd3J6H23zmt6pfYK8NCbFkWpGLuwHNepzL5G3PMZNr6qjyPBrnhfA",
        address: "",
        identifier:
          "did:key:z6Mkr4zjFPqDsoQPo9t17N7pXo5oQXfjCFJ2bFDqpKnf9rBv#z6Mkr4zjFPqDsoQPo9t17N7pXo5oQXfjCFJ2bFDqpKnf9rBv",
      },
    ],
  },
  key_2018_2: {
    didDocument: {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/ed25519-2018/v1",
        "https://w3id.org/security/suites/x25519-2019/v1",
      ],
      id: "did:key:z6MkpVCWpibzht7gFFkBsnNigRvXiQWQgV2vqq8eN8zGkGGN",
      verificationMethod: [
        {
          id: "did:key:z6MkpVCWpibzht7gFFkBsnNigRvXiQWQgV2vqq8eN8zGkGGN#z6MkpVCWpibzht7gFFkBsnNigRvXiQWQgV2vqq8eN8zGkGGN",
          type: "Ed25519VerificationKey2018",
          controller:
            "did:key:z6MkpVCWpibzht7gFFkBsnNigRvXiQWQgV2vqq8eN8zGkGGN",
          publicKeyBase58: "B2wUEUMZNLdD8kuVCDQsqLNXtqEZGbna9pDiXs2Fq3Uz",
        },
      ],
      authentication: [
        "did:key:z6MkpVCWpibzht7gFFkBsnNigRvXiQWQgV2vqq8eN8zGkGGN#z6MkpVCWpibzht7gFFkBsnNigRvXiQWQgV2vqq8eN8zGkGGN",
      ],
      assertionMethod: [
        "did:key:z6MkpVCWpibzht7gFFkBsnNigRvXiQWQgV2vqq8eN8zGkGGN#z6MkpVCWpibzht7gFFkBsnNigRvXiQWQgV2vqq8eN8zGkGGN",
      ],
      capabilityDelegation: [
        "did:key:z6MkpVCWpibzht7gFFkBsnNigRvXiQWQgV2vqq8eN8zGkGGN#z6MkpVCWpibzht7gFFkBsnNigRvXiQWQgV2vqq8eN8zGkGGN",
      ],
      capabilityInvocation: [
        "did:key:z6MkpVCWpibzht7gFFkBsnNigRvXiQWQgV2vqq8eN8zGkGGN#z6MkpVCWpibzht7gFFkBsnNigRvXiQWQgV2vqq8eN8zGkGGN",
      ],
      keyAgreement: [
        {
          id: "did:key:z6MkpVCWpibzht7gFFkBsnNigRvXiQWQgV2vqq8eN8zGkGGN#z6LSr95e5osYAGxuc83dB82EJRVPLFFcoSqZzmVKiqiV8krL",
          type: "X25519KeyAgreementKey2019",
          controller:
            "did:key:z6MkpVCWpibzht7gFFkBsnNigRvXiQWQgV2vqq8eN8zGkGGN",
          publicKeyBase58: "FTuUZW4g4pFAWjfreUWGyqGuV6iW6qfR7nmeEP4xRP5a",
        },
      ],
    },
    keys: [
      {
        id: "did:key:z6MkpVCWpibzht7gFFkBsnNigRvXiQWQgV2vqq8eN8zGkGGN#z6MkpVCWpibzht7gFFkBsnNigRvXiQWQgV2vqq8eN8zGkGGN",
        kty: KTYS.OKP,
        alg: ALGORITHMS.EdDSA,
        format: KEY_FORMATS.BASE58,
        publicKey: "B2wUEUMZNLdD8kuVCDQsqLNXtqEZGbna9pDiXs2Fq3Uz",
        privateKey:
          "7ikaQndFgH8daoLve2h6qDyRdx6LZ1B6g778ScfXGGYrJNwB6heiraN6pShS5SDnQJrRiq2QoZfWzeE9dQXw8sY",
        address: "",
        identifier:
          "did:key:z6MkpVCWpibzht7gFFkBsnNigRvXiQWQgV2vqq8eN8zGkGGN#z6MkpVCWpibzht7gFFkBsnNigRvXiQWQgV2vqq8eN8zGkGGN",
      },
    ],
  },
  key_2020_1: {
    didDocument: {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1",
        "https://w3id.org/security/suites/x25519-2020/v1",
      ],
      id: "did:key:z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw",
      verificationMethod: [
        {
          id: "did:key:z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw#z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw",
          type: "Ed25519VerificationKey2020",
          controller:
            "did:key:z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw",
          publicKeyMultibase:
            "z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw",
        },
      ],
      authentication: [
        "did:key:z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw#z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw",
      ],
      assertionMethod: [
        "did:key:z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw#z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw",
      ],
      capabilityDelegation: [
        "did:key:z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw#z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw",
      ],
      capabilityInvocation: [
        "did:key:z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw#z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw",
      ],
      keyAgreement: [
        {
          id: "did:key:z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw#z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw",
          type: "X25519KeyAgreementKey2020",
          controller:
            "did:key:z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw",
          publicKeyMultibase:
            "z6LSjSGy9kLkMotj3zv1eQEYoo66LaBobzb5EabEhZh72wJQ",
        },
      ],
    },
    keys: [
      {
        id: "did:key:z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw#z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw",
        kty: KTYS.OKP,
        alg: ALGORITHMS.EdDSA,
        format: KEY_FORMATS.BASE58,
        publicKey: "z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw",
        privateKey:
          "zrv1xdp8ZsfXSDh4fQp8sE2VYPmLiCL3RssjKeXW7fYrRkxyWpWR5ugcC36WrCx9FizbJvxdwFmYcq7YxRVC2nVPFp5",
        address: "",
        identifier:
          "did:key:z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw#z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw",
      },
    ],
  },
};

const resolvers = {
  uniResolver: {
    type: "uni",
    methodName: "key",
  },
  ethrResolver: {
    type: "ethr",
    methodName: "key",
  },
};

export const t = [
  {
    name: ethr.ethr_1,
    user: ethr.ethr_2,
  },
  {
    name: key_2018.key_2018_1,
    user: key_2018.key_2018_2,
  },
  {
    name: key_2020.key_2020_1,
    user: key_2020.ke,
  },
];
