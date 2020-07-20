import { KTYS, KEY_FORMATS, ALGORITHMS } from "../src/core/globals";

export const DID_TEST_RESOLVER_DATA = [
    {
        method: 'did:dock',
        did: 'did:dock:5FXqofpV7dsuki925U1dSzDvBuQbaci5yWTQGVWRQ7bdQP5p',
        resolverReturn: {
          "didDocument":{
             "@context":"https://www.w3.org/ns/did/v1",
             "id":"did:dock:5FXqofpV7dsuki925U1dSzDvBuQbaci5yWTQGVWRQ7bdQP5p",
             "assertionMethod":[
                "did:dock:5FXqofpV7dsuki925U1dSzDvBuQbaci5yWTQGVWRQ7bdQP5p#keys-1"
             ],
             "authentication":[
                "did:dock:5FXqofpV7dsuki925U1dSzDvBuQbaci5yWTQGVWRQ7bdQP5p#keys-1"
             ],
             "publicKey":[
                {
                   "id":"did:dock:5FXqofpV7dsuki925U1dSzDvBuQbaci5yWTQGVWRQ7bdQP5p#keys-1",
                   "type":"Ed25519VerificationKey2018",
                   "controller":"did:dock:5H7qVySj4cVga4GmiRpvRQqKCVzoWfE4w1DGV5NGVz2umfu2",
                   "publicKeyBase58":"FY5rfgE9yi56QhMSc221kZN4ZmkjbSXQJTgX52KHJHba"
                }
             ]
          },
          "content":null,
          "contentType":null,
          "resolverMetadata":{
             "duration":280,
             "identifier":"did:dock:5FXqofpV7dsuki925U1dSzDvBuQbaci5yWTQGVWRQ7bdQP5p",
             "driverId":"driver-docknetwork/dock-did-driver",
             "didUrl":{
                "didUrlString":"did:dock:5FXqofpV7dsuki925U1dSzDvBuQbaci5yWTQGVWRQ7bdQP5p",
                "did":{
                   "didString":"did:dock:5FXqofpV7dsuki925U1dSzDvBuQbaci5yWTQGVWRQ7bdQP5p",
                   "method":"dock",
                   "methodSpecificId":"5FXqofpV7dsuki925U1dSzDvBuQbaci5yWTQGVWRQ7bdQP5p",
                   "parseTree":null,
                   "parseRuleCount":null
                },
                "parameters":null,
                "parametersMap":{
       
                },
                "path":"",
                "query":null,
                "fragment":null,
                "parseTree":null,
                "parseRuleCount":null
             }
          },
          "methodMetadata":{
       
          }
        },
        keys: [
            {
              id: 'did:dock:5FXqofpV7dsuki925U1dSzDvBuQbaci5yWTQGVWRQ7bdQP5p#keys-1',
              kty: KTYS.OKP,
              alg: ALGORITHMS.EdDSA,
              format: KEY_FORMATS.BASE58,
              publicKey: 'FY5rfgE9yi56QhMSc221kZN4ZmkjbSXQJTgX52KHJHba'
            }
        ]
    },
    {
      method: 'did:elem',
      did: 'did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A',
      resolverReturn: {
        "didDocument":{
           "@context":"https://w3id.org/did/v1",
           "id":"did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A",
           "service":[
              {
                 "id":"did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#openid",
                 "type":"OpenIdConnectVersion1.0Service",
                 "serviceEndpoint":"https://openid.example.com/"
              }
           ],
           "assertionMethod":[
              "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#edv"
           ],
           "authentication":[
              "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#edv",
              {
                 "id":"did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#authentication",
                 "type":"Ed25519VerificationKey2018",
                 "controller":"did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A",
                 "publicKeyBase58":"H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
              }
           ],
           "capabilityDelegation":[
              "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#edv"
           ],
           "capabilityInvocation":[
              "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#edv"
           ],
           "keyAgreement":[
              {
                 "id":"did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#keyAgreement",
                 "type":"X25519KeyAgreementKey2019",
                 "controller":"did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A",
                 "publicKeyBase58":"ENpfk9K9J6uss5qu6BrAszioE732mYCobmMPSpvB3faM"
              }
           ],
           "publicKey":[
              {
                 "id":"did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#primary",
                 "type":"Secp256k1VerificationKey2018",
                 "controller":"did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A",
                 "publicKeyHex":"0361f286ada2a6b2c74bc6ed44a71ef59fb9dd15eca9283cbe5608aeb516730f33"
              },
              {
                 "id":"did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#recovery",
                 "type":"Secp256k1VerificationKey2018",
                 "controller":"did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A",
                 "publicKeyHex":"02c00982681081372cbb941cd2c9745908316e1373ac333479f0deabcad0e9d574"
              },
              {
                 "id":"did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#edv",
                 "type":"Ed25519VerificationKey2018",
                 "controller":"did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A",
                 "publicKeyBase58":"atEBuHypSkQx7486xT5FUkoBLqvNcWyNK2Xz9EPjdMy"
              },
              {
                 "id":"did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#delegate",
                 "type":"Secp256k1VerificationKey2018",
                 "controller":"did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A",
                 "publicKeyPem":"-----BEGIN PUBLIC KEY\nMIIBCgKCAQEAvzoCEC2rpSpJQaWZbUmlsDNwp83Jr4fi6KmBWIwnj1MZ6CUQ7rBa\nsuLI8AcfX5/10scSfQNCsTLV2tMKQaHuvyrVfwY0dINk+nkqB74QcT2oCCH9XduJ\njDuwWA4xLqAKuF96FsIes52opEM50W7/W7DZCKXkC8fFPFj6QF5ZzApDw2Qsu3yM\nRmr7/W9uWeaTwfPx24YdY7Ah+fdLy3KN40vXv9c4xiSafVvnx9BwYL7H1Q8NiK9L\nGEN6+JSWfgckQCs6UUBOXSZdreNN9zbQCwyzee7bOJqXUDAuLcFARzPw1EsZAyjV\ntGCKIQ0/btqK+jFunT2NBC8RItanDZpptQIDAQAB\nEND PUBLIC KEY-----\r\n"
              },
              {
                 "id":"did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#key-JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw",
                 "type":"Ed25519VerificationKey2018",
                 "controller":"did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A",
                 "publicKeyJwk":{
                    "crv":"secp256k1",
                    "kid":"JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw",
                    "kty":"EC",
                    "x":"dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
                    "y":"36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA"
                 }
              }
           ]
        },
        "content":null,
        "contentType":null,
        "resolverMetadata":{
           "duration":17556,
           "identifier":"did:elem:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A",
           "driverId":"driver-14",
           "didUrl":{
              "didUrlString":"did:elem:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A",
              "did":{
                 "didString":"did:elem:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A",
                 "method":"elem",
                 "methodSpecificId":"EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A",
                 "parseTree":null,
                 "parseRuleCount":null
              },
              "parameters":null,
              "parametersMap":{
     
              },
              "path":"",
              "query":null,
              "fragment":null,
              "parseTree":null,
              "parseRuleCount":null
           }
        },
        "methodMetadata":{
     
        }
      },
      keys: [
        {
          id: 'did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#edv',
          kty: KTYS.OKP,
          alg: ALGORITHMS.EdDSA,
          format: KEY_FORMATS.BASE58,
          publicKey: 'atEBuHypSkQx7486xT5FUkoBLqvNcWyNK2Xz9EPjdMy',
        },
        {
          id: 'did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#authentication',
          kty: KTYS.OKP,
          alg: ALGORITHMS.EdDSA,
          format: KEY_FORMATS.BASE58,
          publicKey: 'H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV',
        }
      ]
    },
    {
      method: 'did:ethr',
      did: 'did:ethr:0xE6Fe788d8ca214A080b0f6aC7F48480b2AEfa9a6',
      resolverReturn: {
        "didDocument":{
           "@context":"https://w3id.org/did/v1",
           "id":"did:ethr:0xE6Fe788d8ca214A080b0f6aC7F48480b2AEfa9a6",
           "authentication":[
              {
                 "type":"Secp256k1SignatureAuthentication2018",
                 "publicKey":[
                    "did:ethr:0xE6Fe788d8ca214A080b0f6aC7F48480b2AEfa9a6#owner"
                 ]
              }
           ],
           "publicKey":[
              {
                 "id":"did:ethr:0xE6Fe788d8ca214A080b0f6aC7F48480b2AEfa9a6#owner",
                 "type":"Secp256k1VerificationKey2018",
                 "ethereumAddress":"0xe6fe788d8ca214a080b0f6ac7f48480b2aefa9a6",
                 "owner":"did:ethr:0xE6Fe788d8ca214A080b0f6aC7F48480b2AEfa9a6"
              },
              {
                 "id":"did:ethr:0xE6Fe788d8ca214A080b0f6aC7F48480b2AEfa9a6#delegate-1",
                 "type":"Secp256k1VerificationKey2018",
                 "owner":"did:ethr:0xE6Fe788d8ca214A080b0f6aC7F48480b2AEfa9a6",
                 "publicKeyHex":"0295dda1dca7f80e308ef60155ddeac00e46b797fd40ef407f422e88d2467a27eb"
              }
           ]
        },
        "content":null,
        "contentType":null,
        "resolverMetadata":{
           "duration":2582,
           "identifier":"did:ethr:0xE6Fe788d8ca214A080b0f6aC7F48480b2AEfa9a6",
           "driverId":"driver-uport/uni-resolver-driver-did-uport-9",
           "didUrl":{
              "didUrlString":"did:ethr:0xE6Fe788d8ca214A080b0f6aC7F48480b2AEfa9a6",
              "did":{
                 "didString":"did:ethr:0xE6Fe788d8ca214A080b0f6aC7F48480b2AEfa9a6",
                 "method":"ethr",
                 "methodSpecificId":"0xE6Fe788d8ca214A080b0f6aC7F48480b2AEfa9a6",
                 "parseTree":null,
                 "parseRuleCount":null
              },
              "parameters":null,
              "parametersMap":{
     
              },
              "path":"",
              "query":null,
              "fragment":null,
              "parseTree":null,
              "parseRuleCount":null
           }
        },
        "methodMetadata":{
     
        }
      },
      keys: [
        {
          id: 'did:ethr:0xE6Fe788d8ca214A080b0f6aC7F48480b2AEfa9a6#owner',
          kty: KTYS.EC,
          alg: ALGORITHMS["ES256K-R"],
          format: KEY_FORMATS.ETHEREUM_ADDRESS,
          publicKey: '0xE6Fe788d8ca214A080b0f6aC7F48480b2AEfa9a6'
        },
      ]
    }
]

export const invalidDID = 'did:eth:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83';