import { KTYS, KEY_FORMATS, ALGORITHMS } from "../src/core/globals";

export const DID_TEST_RESOLVER_DATA = [
   {
      method: 'did:btcr',
      did:'did:btcr:x705-jznz-q3nl-srs',
      resolverReturn: {
         "didDocument":{
            "@context":"https://www.w3.org/2019/did/v1",
            "id":"did:btcr:x705-jznz-q3nl-srs",
            "service":[
      
            ],
            "authentication":[
               {
                  "type":"EcdsaSecp256k1SignatureAuthentication2019",
                  "publicKey":[
                     "#satoshi"
                  ]
               }
            ],
            "publicKey":[
               {
                  "id":"did:btcr:x705-jznz-q3nl-srs#key-0",
                  "type":"EcdsaSecp256k1VerificationKey2019",
                  "publicKeyHex":"02e0e01a8c302976e1556e95c54146e8464adac8626a5d29474718a7281133ff49"
               },
               {
                  "id":"did:btcr:x705-jznz-q3nl-srs#key-1",
                  "type":"EcdsaSecp256k1VerificationKey2019",
                  "publicKeyHex":"02e0e01a8c302976e1556e95c54146e8464adac8626a5d29474718a7281133ff49"
               },
               {
                  "id":"did:btcr:x705-jznz-q3nl-srs#satoshi",
                  "type":"EcdsaSecp256k1VerificationKey2019",
                  "publicKeyHex":"02e0e01a8c302976e1556e95c54146e8464adac8626a5d29474718a7281133ff49"
               }
            ]
         },
         "content":null,
         "contentType":null,
         "resolverMetadata":{
            "duration":187,
            "identifier":"did:btcr:x705-jznz-q3nl-srs",
            "driverId":"driver-universalresolver/driver-did-btcr",
            "didUrl":{
               "didUrlString":"did:btcr:x705-jznz-q3nl-srs",
               "did":{
                  "didString":"did:btcr:x705-jznz-q3nl-srs",
                  "method":"btcr",
                  "methodSpecificId":"x705-jznz-q3nl-srs",
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
            "inputScriptPubKey":"02e0e01a8c302976e1556e95c54146e8464adac8626a5d29474718a7281133ff49",
            "continuationUri":null,
            "chain":"TESTNET",
            "initialBlockHeight":1353983,
            "initialTransactionPosition":83,
            "initialTxoIndex":0,
            "initialTxid":{
               "chain":"TESTNET",
               "txid":"80871cf043c1d96f3d716f5bc02daa15a5e534b2a00e81a530fb40aa07ceceb6",
               "txoIndex":0
            },
            "blockHeight":1354004,
            "transactionPosition":195,
            "txoIndex":0,
            "txid":{
               "chain":"TESTNET",
               "txid":"be5be4b2c4e530b49af139a8448ae2ae8b5882f2e7f5c7908eca0268f72494e9",
               "txoIndex":0
            },
            "spentInChainAndTxids":[
               {
                  "spentInChainAndTxid":{
                     "chain":"TESTNET",
                     "txid":"be5be4b2c4e530b49af139a8448ae2ae8b5882f2e7f5c7908eca0268f72494e9",
                     "txoIndex":0
                  },
                  "inputScriptPubKey":"02e0e01a8c302976e1556e95c54146e8464adac8626a5d29474718a7281133ff49",
                  "continuationUri":null,
                  "transactionTime":0
               }
            ],
            "deactivated":true
         }
      },
      keys: [
         {
            id: 'did:btcr:x705-jznz-q3nl-srs#satoshi',
            kty: KTYS.EC,
            alg: ALGORITHMS.ES256K,
            format: KEY_FORMATS.HEX,
            publicKey: '02e0e01a8c302976e1556e95c54146e8464adac8626a5d29474718a7281133ff49'
         }
      ]
   },
   {
      method: 'did:btcr',
      did: 'did:btcr:xkrn-xz7q-qsye-28p',
      resolverReturn: {
         "didDocument":{
            "@context":[
               "https://www.w3.org/2019/did/v1"
            ],
            "id":"did:btcr:xkrn-xz7q-qsye-28p",
            "authentication":[
               {
                  "type":"EcdsaSecp256k1SignatureAuthentication2019",
                  "publicKey":[
                     "#satoshi"
                  ]
               }
            ],
            "publicKey":[
               {
                  "id":"did:btcr:xkrn-xz7q-qsye-28p#key-0",
                  "type":"EcdsaSecp256k1VerificationKey2019",
                  "publicKeyHex":"024a63c4362772b0fafc51ac02470dae3f8da8a05d90bae9e1ef3f5243180120dd"
               },
               {
                  "id":"did:btcr:xkrn-xz7q-qsye-28p#key-1",
                  "type":"EcdsaSecp256k1VerificationKey2019",
                  "publicKeyHex":"02b5470c5c0557ef7548dec23220d4d75f8c4aa1b459c190f100f4f78a1adb215b"
               },
               {
                  "id":"did:btcr:xkrn-xz7q-qsye-28p#key-2",
                  "type":"EcdsaSecp256k1VerificationKey2019",
                  "publicKeyHex":"02e2078417a258acc2c9f9eb856b35b508d1e5a23fc1dcf94fd6f7337b1cb7fb90"
               },
               {
                  "id":"did:btcr:xkrn-xz7q-qsye-28p#key-3",
                  "type":"EcdsaSecp256k1VerificationKey2019",
                  "publicKeyHex":"02074f9b37f26ae410742ec754b02b3f7d078ff73d7e06b6f7a670d5701805ef82"
               },
               {
                  "id":"did:btcr:xkrn-xz7q-qsye-28p#key-4",
                  "type":"EcdsaSecp256k1VerificationKey2019",
                  "publicKeyHex":"02b4021b6907fbc12b2c0d9278d21bc0f371a56b553fc75eaf75b79d925301f7a4"
               },
               {
                  "id":"did:btcr:xkrn-xz7q-qsye-28p#key-5",
                  "type":"EcdsaSecp256k1VerificationKey2019",
                  "publicKeyHex":"03479e1bde881c15edc82b7c4d0d04441c5e7f6dce4b703f43c5d5c12948df32d2"
               },
               {
                  "id":"did:btcr:xkrn-xz7q-qsye-28p#satoshi",
                  "type":"EcdsaSecp256k1VerificationKey2019",
                  "publicKeyHex":"03479e1bde881c15edc82b7c4d0d04441c5e7f6dce4b703f43c5d5c12948df32d2"
               }
            ]
         },
         "content":null,
         "contentType":null,
         "resolverMetadata":{
            "duration":250,
            "identifier":"did:btcr:xkrn-xz7q-qsye-28p",
            "driverId":"driver-universalresolver/driver-did-btcr",
            "didUrl":{
               "didUrlString":"did:btcr:xkrn-xz7q-qsye-28p",
               "did":{
                  "didString":"did:btcr:xkrn-xz7q-qsye-28p",
                  "method":"btcr",
                  "methodSpecificId":"xkrn-xz7q-qsye-28p",
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
            "inputScriptPubKey":"03479e1bde881c15edc82b7c4d0d04441c5e7f6dce4b703f43c5d5c12948df32d2",
            "continuationUri":"https://raw.githubusercontent.com/peacekeeper/self/master/ddo",
            "continuation":{
               "@context":"https://www.w3.org/2019/did/v1",
               "id":"did:btcr:xkrn-xz7q-qsye-28p"
            },
            "chain":"TESTNET",
            "initialBlockHeight":1156667,
            "initialTransactionPosition":30,
            "initialTxoIndex":0,
            "initialTxid":{
               "chain":"TESTNET",
               "txid":"b01a3498ff817def5017e0c17c9171c4e19cced1a6a63d67f617ac06fe5baf96",
               "txoIndex":0
            },
            "blockHeight":1202316,
            "transactionPosition":80,
            "txoIndex":0,
            "txid":{
               "chain":"TESTNET",
               "txid":"5310788c3f8c47d2e0336a4de7ecaceb52405699b571bd1254bf4580caf66950",
               "txoIndex":0
            },
            "spentInChainAndTxids":[
               {
                  "spentInChainAndTxid":{
                     "chain":"TESTNET",
                     "txid":"3a966c8b2254a73ee594498a55e5d6746f9e66df44730217a1ffe045f83b79a7",
                     "txoIndex":0
                  },
                  "inputScriptPubKey":"024a63c4362772b0fafc51ac02470dae3f8da8a05d90bae9e1ef3f5243180120dd",
                  "continuationUri":"https://raw.githubusercontent.com/peacekeeper/self/master/ddo",
                  "transactionTime":0
               },
               {
                  "spentInChainAndTxid":{
                     "chain":"TESTNET",
                     "txid":"06dff479edb2ad0bf4dc2d970518207f80673b47832f823317719fda900acddb",
                     "txoIndex":0
                  },
                  "inputScriptPubKey":"02b5470c5c0557ef7548dec23220d4d75f8c4aa1b459c190f100f4f78a1adb215b",
                  "continuationUri":"https://raw.githubusercontent.com/peacekeeper/self/master/ddo",
                  "transactionTime":0
               },
               {
                  "spentInChainAndTxid":{
                     "chain":"TESTNET",
                     "txid":"dd0c39bc488b3e154f460920e6e6f1cf1b308736348d28dc2d126907e10e4800",
                     "txoIndex":0
                  },
                  "inputScriptPubKey":"02e2078417a258acc2c9f9eb856b35b508d1e5a23fc1dcf94fd6f7337b1cb7fb90",
                  "continuationUri":"https://raw.githubusercontent.com/peacekeeper/self/master/ddo",
                  "transactionTime":0
               },
               {
                  "spentInChainAndTxid":{
                     "chain":"TESTNET",
                     "txid":"a8150d3d1e7e635314ca0bd2b8976aa5d98d46f7bd64dfc850969586afb2526e",
                     "txoIndex":0
                  },
                  "inputScriptPubKey":"02074f9b37f26ae410742ec754b02b3f7d078ff73d7e06b6f7a670d5701805ef82",
                  "continuationUri":"https://raw.githubusercontent.com/peacekeeper/self/master/ddo",
                  "transactionTime":0
               },
               {
                  "spentInChainAndTxid":{
                     "chain":"TESTNET",
                     "txid":"5310788c3f8c47d2e0336a4de7ecaceb52405699b571bd1254bf4580caf66950",
                     "txoIndex":0
                  },
                  "inputScriptPubKey":"02b4021b6907fbc12b2c0d9278d21bc0f371a56b553fc75eaf75b79d925301f7a4",
                  "continuationUri":"https://raw.githubusercontent.com/peacekeeper/self/master/ddo",
                  "transactionTime":0
               }
            ],
            "deactivated":false
         }
      },
      keys: [
         {
            id: 'did:btcr:xkrn-xz7q-qsye-28p#satoshi',
            kty: KTYS.EC,
            alg: ALGORITHMS.ES256K,
            format: KEY_FORMATS.HEX,
            publicKey: '03479e1bde881c15edc82b7c4d0d04441c5e7f6dce4b703f43c5d5c12948df32d2'
         },
      ]
   },
   {
      method: 'did:btcr',
      did: 'did:btcr:xksa-czpq-qxr3-l8k',
      resolverReturn: {
         "didDocument":{
            "@context":"https://www.w3.org/2019/did/v1",
            "id":"did:btcr:xksa-czpq-qxr3-l8k",
            "service":[
      
            ],
            "authentication":[
               {
                  "type":"EcdsaSecp256k1SignatureAuthentication2019",
                  "publicKey":[
                     "#satoshi"
                  ]
               }
            ],
            "publicKey":[
               {
                  "id":"did:btcr:xksa-czpq-qxr3-l8k#key-0",
                  "type":"EcdsaSecp256k1VerificationKey2019",
                  "publicKeyHex":"03aa0d1f6177a7f27dfabe51b1442057ca1bf9bede4f857d92203a165302834693"
               },
               {
                  "id":"did:btcr:xksa-czpq-qxr3-l8k#satoshi",
                  "type":"EcdsaSecp256k1VerificationKey2019",
                  "publicKeyHex":"03aa0d1f6177a7f27dfabe51b1442057ca1bf9bede4f857d92203a165302834693"
               }
            ]
         },
         "content":null,
         "contentType":null,
         "resolverMetadata":{
            "duration":61,
            "identifier":"did:btcr:xksa-czpq-qxr3-l8k",
            "driverId":"driver-universalresolver/driver-did-btcr",
            "didUrl":{
               "didUrlString":"did:btcr:xksa-czpq-qxr3-l8k",
               "did":{
                  "didString":"did:btcr:xksa-czpq-qxr3-l8k",
                  "method":"btcr",
                  "methodSpecificId":"xksa-czpq-qxr3-l8k",
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
            "inputScriptPubKey":"03aa0d1f6177a7f27dfabe51b1442057ca1bf9bede4f857d92203a165302834693",
            "continuationUri":null,
            "chain":"TESTNET",
            "initialBlockHeight":1456907,
            "initialTransactionPosition":1,
            "initialTxoIndex":0,
            "initialTxid":{
               "chain":"TESTNET",
               "txid":"eac139503dddaeeed8d8a169b0ae2d893c355ee610bf95eb0317a1eb86757af3",
               "txoIndex":0
            },
            "blockHeight":1456907,
            "transactionPosition":1,
            "txoIndex":0,
            "txid":{
               "chain":"TESTNET",
               "txid":"eac139503dddaeeed8d8a169b0ae2d893c355ee610bf95eb0317a1eb86757af3",
               "txoIndex":0
            },
            "spentInChainAndTxids":[
      
            ],
            "deactivated":false
         }
      },
      keys: [
         {
            id: 'did:btcr:xksa-czpq-qxr3-l8k#satoshi',
            kty: KTYS.EC,
            alg: ALGORITHMS.ES256K,
            format: KEY_FORMATS.HEX,
            publicKey: '03aa0d1f6177a7f27dfabe51b1442057ca1bf9bede4f857d92203a165302834693'
         }
      ]
   },
   {
      method: 'did:btcr',
      did: 'did:btcr:xkyt-fzzq-q23l-k4n',
      resolverReturn: {
         "didDocument":{
            "@context":[
               "https://w3id.org/did/v1"
            ],
            "id":"did:btcr:xkyt-fzzq-q23l-k4n",
            "authentication":[
               {
                  "type":"EcdsaSecp256k1SignatureAuthentication2019",
                  "publicKey":[
                     "#satoshi"
                  ]
               },
               {
                  "type":"RsaSignatureAuthentication2018",
                  "publicKey":[
                     "#keys-2"
                  ]
               }
            ],
            "publicKey":[
               {
                  "id":"did:btcr:xkyt-fzzq-q23l-k4n#key-0",
                  "type":"EcdsaSecp256k1VerificationKey2019",
                  "publicKeyHex":"0280e0b456b9e97eecb8028215664c5b99ffa79628b60798edd9d562c6db1e4f85"
               },
               {
                  "id":"did:btcr:xkyt-fzzq-q23l-k4n#satoshi",
                  "type":"EcdsaSecp256k1VerificationKey2019",
                  "publicKeyHex":"0280e0b456b9e97eecb8028215664c5b99ffa79628b60798edd9d562c6db1e4f85"
               },
               {
                  "id":"#keys-2",
                  "type":"RsaVerificationKey2018",
                  "publicKeyPem":"-----BEGIN PUBLIC KEY...END PUBLIC KEY-----\r\n"
               }
            ]
         },
         "content":null,
         "contentType":null,
         "resolverMetadata":{
            "duration":104,
            "identifier":"did:btcr:xkyt-fzzq-q23l-k4n",
            "driverId":"driver-universalresolver/driver-did-btcr",
            "didUrl":{
               "didUrlString":"did:btcr:xkyt-fzzq-q23l-k4n",
               "did":{
                  "didString":"did:btcr:xkyt-fzzq-q23l-k4n",
                  "method":"btcr",
                  "methodSpecificId":"xkyt-fzzq-q23l-k4n",
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
            "inputScriptPubKey":"0280e0b456b9e97eecb8028215664c5b99ffa79628b60798edd9d562c6db1e4f85",
            "continuationUri":"https://raw.githubusercontent.com/kimdhamilton/did/master/ddo.jsonld",
            "continuation":{
               "@context":"https://w3id.org/did/v1",
               "publicKey":[
                  {
                     "id":"#keys-2",
                     "type":"RsaVerificationKey2018",
                     "publicKeyPem":"-----BEGIN PUBLIC KEY...END PUBLIC KEY-----\r\n"
                  }
               ],
               "authentication":[
                  {
                     "type":"RsaSignatureAuthentication2018",
                     "publicKey":"#keys-2"
                  }
               ]
            },
            "chain":"TESTNET",
            "initialBlockHeight":1201739,
            "initialTransactionPosition":2,
            "initialTxoIndex":0,
            "initialTxid":{
               "chain":"TESTNET",
               "txid":"67c0ee676221d9e0e08b98a55a8bf8add9cba854f13dda393e38ffa1b982b833",
               "txoIndex":0
            },
            "blockHeight":1201739,
            "transactionPosition":2,
            "txoIndex":0,
            "txid":{
               "chain":"TESTNET",
               "txid":"67c0ee676221d9e0e08b98a55a8bf8add9cba854f13dda393e38ffa1b982b833",
               "txoIndex":0
            },
            "spentInChainAndTxids":[
      
            ],
            "deactivated":false
         }
      },
      keys: [
         {
            id: 'did:btcr:xkyt-fzzq-q23l-k4n#satoshi',
            kty: KTYS.EC,
            alg: ALGORITHMS.ES256K,
            format: KEY_FORMATS.HEX,
            publicKey: '0280e0b456b9e97eecb8028215664c5b99ffa79628b60798edd9d562c6db1e4f85'
         }
      ]
   },
   {
      method: 'did:cpp',
      did: 'did:ccp:ceNobbK6Me9F5zwyE3MKY88QZLw',
      resolverReturn: {
      "didDocument":{
         "@context":"https://www.w3.org/2019/did/v1",
         "id":"did:ccp:ceNobbK6Me9F5zwyE3MKY88QZLw",
         "service":[
            {
               "type":"DIDResolve",
               "serviceEndpoint":"https://did.baidu.com"
            }
         ],
         "authentication":[
            {
               "type":"Secp256k1",
               "publicKey":[
                  "did:ccp:ceNobbK6Me9F5zwyE3MKY88QZLw#key-1"
               ]
            }
         ],
         "publicKey":[
            {
               "id":"did:ccp:ceNobbK6Me9F5zwyE3MKY88QZLw#key-1",
               "type":"Secp256k1",
               "publicKeyHex":"046fcbedd1107ca45be3e81fc445e5a366886a89e7087fe3d128e6236302f31594740f250433ebe9f0abcbd04dbf9c5979e270a0772ad1cc502cec2d5de9504c8c"
            },
            {
               "id":"did:ccp:ceNobbK6Me9F5zwyE3MKY88QZLw#key-2",
               "type":"Secp256k1",
               "publicKeyHex":"0496712d16b0836684aacd5ab6ba3d489c35efa31f414a1c6a455fc6b37ff28e5fa97ac29c1021b76e5b78e2bbceac1dfc4ec98e6b2b3e65a29f7f1cd4944dfb93"
            }
         ]
      },
      "content":null,
      "contentType":null,
      "resolverMetadata":{
         "duration":2726,
         "identifier":"did:ccp:ceNobbK6Me9F5zwyE3MKY88QZLw",
         "driverId":"driver-hello2mao/driver-did-ccp",
         "didUrl":{
            "didUrlString":"did:ccp:ceNobbK6Me9F5zwyE3MKY88QZLw",
            "did":{
               "didString":"did:ccp:ceNobbK6Me9F5zwyE3MKY88QZLw",
               "method":"ccp",
               "methodSpecificId":"ceNobbK6Me9F5zwyE3MKY88QZLw",
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
         "version":2,
         "proof":{
            "creator":"did:ccp:ceNobbK6Me9F5zwyE3MKY88QZLw#key-1",
            "type":"Secp256k1",
            "signatureValue":"30440220211ffc76ae2858d6baa29faa9b576d6b2e048e8f4f7767ee1c2fba7ae6c2a78102205f5b56cd1431830b45109d716631638d961e5b252c2c2354d8bb96782d8a62ef"
         },
         "created":"2019-10-21T11:12:13.065Z",
         "updated":"2019-10-21T11:17:49.379Z"
      }
      },
      keys: [
      {
         id: 'did:ccp:ceNobbK6Me9F5zwyE3MKY88QZLw#key-1',
         kty: KTYS.EC,
         alg: ALGORITHMS.ES256K,
         format: KEY_FORMATS.HEX,
         publicKey: '046fcbedd1107ca45be3e81fc445e5a366886a89e7087fe3d128e6236302f31594740f250433ebe9f0abcbd04dbf9c5979e270a0772ad1cc502cec2d5de9504c8c'
      },
      {
         id: 'did:ccp:ceNobbK6Me9F5zwyE3MKY88QZLw#key-2',
         kty: KTYS.EC,
         alg: ALGORITHMS.ES256K,
         format: KEY_FORMATS.HEX,
         publicKey: '0496712d16b0836684aacd5ab6ba3d489c35efa31f414a1c6a455fc6b37ff28e5fa97ac29c1021b76e5b78e2bbceac1dfc4ec98e6b2b3e65a29f7f1cd4944dfb93'
      }
      ]
   },
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
   },
   {
      method: 'did:factom',
      did: 'did:factom:testnet:6aa7d4afe4932885b5b6e93accb5f4f6c14bd1827733e05e3324ae392c0b2764',
      resolverReturn: {
         "didDocument":{
            "@context":"https://www.w3.org/ns/did/v1",
            "id":"did:factom:testnet:6aa7d4afe4932885b5b6e93accb5f4f6c14bd1827733e05e3324ae392c0b2764",
            "assertionMethod":[
               "did:factom:testnet:6aa7d4afe4932885b5b6e93accb5f4f6c14bd1827733e05e3324ae392c0b2764#key-1"
            ],
            "authentication":[
               "did:factom:testnet:6aa7d4afe4932885b5b6e93accb5f4f6c14bd1827733e05e3324ae392c0b2764#key-1"
            ],
            "publicKey":[
               {
                  "id":"did:factom:testnet:6aa7d4afe4932885b5b6e93accb5f4f6c14bd1827733e05e3324ae392c0b2764#key-0",
                  "type":"Ed25519VerificationKey2018",
                  "controller":"did:factom:testnet:6aa7d4afe4932885b5b6e93accb5f4f6c14bd1827733e05e3324ae392c0b2764",
                  "publicKeyBase58":"Dz5LsutgY97gSo64yx7ReCNictXQuQvSqipHNLMcPPo9"
               },
               {
                  "id":"did:factom:testnet:6aa7d4afe4932885b5b6e93accb5f4f6c14bd1827733e05e3324ae392c0b2764#key-1",
                  "type":"Ed25519VerificationKey2018",
                  "controller":"did:factom:testnet:6aa7d4afe4932885b5b6e93accb5f4f6c14bd1827733e05e3324ae392c0b2764",
                  "publicKeyBase58":"AiL9wEJSGHF8UH3rad1keCgFtCQGdgdowRJ9h1JN7LXn"
               }
            ]
         },
         "content":null,
         "contentType":null,
         "resolverMetadata":{
            "duration":1006,
            "identifier":"did:factom:testnet:6aa7d4afe4932885b5b6e93accb5f4f6c14bd1827733e05e3324ae392c0b2764",
            "driverId":"driver-sphereon/driver-did-factom",
            "didUrl":{
               "didUrlString":"did:factom:testnet:6aa7d4afe4932885b5b6e93accb5f4f6c14bd1827733e05e3324ae392c0b2764",
               "did":{
                  "didString":"did:factom:testnet:6aa7d4afe4932885b5b6e93accb5f4f6c14bd1827733e05e3324ae392c0b2764",
                  "method":"factom",
                  "methodSpecificId":"testnet:6aa7d4afe4932885b5b6e93accb5f4f6c14bd1827733e05e3324ae392c0b2764",
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
            "factomdNode":"https://dev.factomd.net/v2",
            "chainCreationEntryHash":"4eb1a96667a5d539b76a91df081e53988c9cdc55f0656aa0a2558ff7fdc922ea",
            "resolvedFactomIdentity":{
               "identity":{
                  "version":1,
                  "keys":[
                     "idpub3DmK34ASFcTmVkssMSa252WHw1i378od2JhwHLndJTFKN463Zn",
                     "idpub2rMgxiN6KJZDqGwADn9JVobwksU9VvXGK7uuMh3RKAnA68dArn"
                  ]
               },
               "metadata":{
                  "creation":{
                     "blockHeight":125486,
                     "entryTimestamp":1585952760,
                     "blockTimestamp":1585952520,
                     "entryHash":"4eb1a96667a5d539b76a91df081e53988c9cdc55f0656aa0a2558ff7fdc922ea"
                  },
                  "update":{
                     "blockHeight":125486,
                     "entryTimestamp":1585952760,
                     "blockTimestamp":1585952520,
                     "entryHash":"1626a1ab198ca2ce973a5876dbfafcbfd098a718d44538b248565ca4d3381225"
                  }
               }
            },
            "currentEntryTimestamp":1585952760,
            "currentBlockHeight":125486,
            "chainCreationEntryTimestamp":1585952760,
            "chainCreationBlockTimestamp":1585952520,
            "chainCreationBlockHeight":125486,
            "currentEntryHash":"1626a1ab198ca2ce973a5876dbfafcbfd098a718d44538b248565ca4d3381225",
            "currentBlockTimestamp":1585952520,
            "network":"testnet"
         }
      },
      keys: [
         {
            id: 'did:factom:testnet:6aa7d4afe4932885b5b6e93accb5f4f6c14bd1827733e05e3324ae392c0b2764#key-1',
            kty: KTYS.OKP,
            alg: ALGORITHMS.EdDSA,
            format: KEY_FORMATS.BASE58,
            publicKey: 'AiL9wEJSGHF8UH3rad1keCgFtCQGdgdowRJ9h1JN7LXn'
         }
      ]
   },
   {
      method: 'did:key',
      did: 'did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6',
      resolverReturn: {
         "didDocument":{
            "@context":[
               "https://w3id.org/did/v0.11"
            ],
            "id":"did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6",
            "assertionMethod":[
               "did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6#z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6"
            ],
            "authentication":[
               "did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6#z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6"
            ],
            "capabilityDelegation":[
               "did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6#z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6"
            ],
            "capabilityInvocation":[
               "did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6#z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6"
            ],
            "keyAgreement":[
               {
                  "id":"did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6#z6LSbgq3GejX88eiAYWmZ9EiddS3GaXodvm8MJJyEH7bqXgz",
                  "type":"X25519KeyAgreementKey2019",
                  "controller":"did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6",
                  "publicKeyBase58":"1eskLvf2fvy5A912VimK3DZRRzgwKayUKbHjpU589vE"
               }
            ],
            "publicKey":[
               {
                  "id":"did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6#z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6",
                  "type":"Ed25519VerificationKey2018",
                  "controller":"did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6",
                  "publicKeyBase58":"2QTnR7atrFu3Y7S6Xmmr4hTsMaL1KDh6Mpe9MgnJugbi"
               }
            ]
         },
         "content":null,
         "contentType":null,
         "resolverMetadata":{
            "duration":17,
            "identifier":"did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6",
            "driverId":"driver-universalresolver/driver-did-key",
            "didUrl":{
               "didUrlString":"did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6",
               "did":{
                  "didString":"did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6",
                  "method":"key",
                  "methodSpecificId":"z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6",
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
            id: 'did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6#z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6',
            kty: KTYS.OKP,
            alg: ALGORITHMS.EdDSA,
            format: KEY_FORMATS.BASE58,
            publicKey: '2QTnR7atrFu3Y7S6Xmmr4hTsMaL1KDh6Mpe9MgnJugbi'
         }
      ]
   },
   {
      method: 'did:kilt',
      did: 'did:kilt:5GFs8gCumJcZDDWof5ETFqDFEsNwCsVJUj2bX7y4xBLxN5qT',
      resolverReturn: {
         "didDocument":{
            "@context":"https://w3id.org/did/v1",
            "id":"did:kilt:5GFs8gCumJcZDDWof5ETFqDFEsNwCsVJUj2bX7y4xBLxN5qT",
            "service":[
               {
                  "type":"KiltMessagingService",
                  "serviceEndpoint":"messaging"
               }
            ],
            "authentication":[
               {
                  "type":"Ed25519SignatureAuthentication2018",
                  "publicKey":[
                     "did:kilt:5GFs8gCumJcZDDWof5ETFqDFEsNwCsVJUj2bX7y4xBLxN5qT#key-1"
                  ]
               }
            ],
            "publicKey":[
               {
                  "id":"did:kilt:5GFs8gCumJcZDDWof5ETFqDFEsNwCsVJUj2bX7y4xBLxN5qT#key-1",
                  "type":"Ed25519VerificationKey2018",
                  "controller":"did:kilt:5GFs8gCumJcZDDWof5ETFqDFEsNwCsVJUj2bX7y4xBLxN5qT",
                  "publicKeyHex":"0xb973dbeb639d1ccbe143c3f38e95afbc9951b6bc2bc865ab3fe1fa0dacd92816"
               },
               {
                  "id":"did:kilt:5GFs8gCumJcZDDWof5ETFqDFEsNwCsVJUj2bX7y4xBLxN5qT#key-2",
                  "type":"X25519Salsa20Poly1305Key2018",
                  "controller":"did:kilt:5GFs8gCumJcZDDWof5ETFqDFEsNwCsVJUj2bX7y4xBLxN5qT",
                  "publicKeyHex":"0x4a087176d183ff29cb3ddd55f3f804ef2c719232ad71ebd3dc29f47a24d91e7a"
               }
            ]
         },
         "content":null,
         "contentType":null,
         "resolverMetadata":{
            "duration":134,
            "identifier":"did:kilt:5GFs8gCumJcZDDWof5ETFqDFEsNwCsVJUj2bX7y4xBLxN5qT",
            "driverId":"driver-kiltprotocol/kilt-did-driver",
            "didUrl":{
               "didUrlString":"did:kilt:5GFs8gCumJcZDDWof5ETFqDFEsNwCsVJUj2bX7y4xBLxN5qT",
               "did":{
                  "didString":"did:kilt:5GFs8gCumJcZDDWof5ETFqDFEsNwCsVJUj2bX7y4xBLxN5qT",
                  "method":"kilt",
                  "methodSpecificId":"5GFs8gCumJcZDDWof5ETFqDFEsNwCsVJUj2bX7y4xBLxN5qT",
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
            id: 'did:kilt:5GFs8gCumJcZDDWof5ETFqDFEsNwCsVJUj2bX7y4xBLxN5qT#key-1',
            kty: KTYS.OKP,
            alg: ALGORITHMS.EdDSA,
            format: KEY_FORMATS.HEX,
            publicKey: '0xb973dbeb639d1ccbe143c3f38e95afbc9951b6bc2bc865ab3fe1fa0dacd92816'
         }
      ]
   },
   {
      method: 'did:nacl',
      did: 'did:nacl:Md8JiMIwsapml_FtQ2ngnGftNP5UmVCAUuhnLyAsPxI',
      resolverReturn: {
         "didDocument":{
            "@context":"https://w3id.org/did/v1",
            "id":"did:nacl:Md8JiMIwsapml_FtQ2ngnGftNP5UmVCAUuhnLyAsPxI",
            "authentication":[
               {
                  "type":"ED25519SigningAuthentication",
                  "publicKey":[
                     "did:nacl:Md8JiMIwsapml_FtQ2ngnGftNP5UmVCAUuhnLyAsPxI#key1"
                  ]
               }
            ],
            "publicKey":[
               {
                  "id":"did:nacl:Md8JiMIwsapml_FtQ2ngnGftNP5UmVCAUuhnLyAsPxI#key1",
                  "type":"ED25519SignatureVerification",
                  "owner":"did:nacl:Md8JiMIwsapml_FtQ2ngnGftNP5UmVCAUuhnLyAsPxI",
                  "publicKeyBase64":"Md8JiMIwsapml/FtQ2ngnGftNP5UmVCAUuhnLyAsPxI="
               },
               {
                  "id":"did:nacl:Md8JiMIwsapml_FtQ2ngnGftNP5UmVCAUuhnLyAsPxI#key2",
                  "type":"Curve25519EncryptionPublicKey",
                  "owner":"did:nacl:Md8JiMIwsapml_FtQ2ngnGftNP5UmVCAUuhnLyAsPxI",
                  "publicKeyBase64":"OAsnUyuUBISGsOherdxO6rgzUeGe9SnffDXQk6KpkAY="
               }
            ]
         },
         "content":null,
         "contentType":null,
         "resolverMetadata":{
            "duration":17,
            "identifier":"did:nacl:Md8JiMIwsapml_FtQ2ngnGftNP5UmVCAUuhnLyAsPxI",
            "driverId":"driver-uport/uni-resolver-driver-did-uport-10",
            "didUrl":{
               "didUrlString":"did:nacl:Md8JiMIwsapml_FtQ2ngnGftNP5UmVCAUuhnLyAsPxI",
               "did":{
                  "didString":"did:nacl:Md8JiMIwsapml_FtQ2ngnGftNP5UmVCAUuhnLyAsPxI",
                  "method":"nacl",
                  "methodSpecificId":"Md8JiMIwsapml_FtQ2ngnGftNP5UmVCAUuhnLyAsPxI",
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
            id: 'did:nacl:Md8JiMIwsapml_FtQ2ngnGftNP5UmVCAUuhnLyAsPxI#key1',
            kty: KTYS.OKP,
            alg: ALGORITHMS.EdDSA,
            format: KEY_FORMATS.BASE64,
            publicKey: 'Md8JiMIwsapml/FtQ2ngnGftNP5UmVCAUuhnLyAsPxI='
         }
      ]
   },
   {
      method: 'did:ont',
      did: 'did:ont:AN5g6gz9EoQ3sCNu7514GEghZurrktCMiH',
      resolverReturn: {
         "didDocument":{
            "@context":"https://w3id.org/did/v1",
            "id":"did:ont:AN5g6gz9EoQ3sCNu7514GEghZurrktCMiH",
            "authentication":[
               "did:ont:AN5g6gz9EoQ3sCNu7514GEghZurrktCMiH#keys-1"
            ],
            "controller":"",
            "publicKey":[
               {
                  "id":"did:ont:AN5g6gz9EoQ3sCNu7514GEghZurrktCMiH#keys-1",
                  "type":"EcdsaSecp256r1VerificationKey2019",
                  "controller":"did:ont:AN5g6gz9EoQ3sCNu7514GEghZurrktCMiH",
                  "publicKeyHex":"023b041dfc2d00a9846d291dd4bad3f32b8c13a6ad8dc2e97fd711888ed7818c66"
               }
            ]
         },
         "content":null,
         "contentType":null,
         "resolverMetadata":{
            "duration":109,
            "identifier":"did:ont:AN5g6gz9EoQ3sCNu7514GEghZurrktCMiH",
            "driverId":"driver-ontio/ontid-driver",
            "didUrl":{
               "didUrlString":"did:ont:AN5g6gz9EoQ3sCNu7514GEghZurrktCMiH",
               "did":{
                  "didString":"did:ont:AN5g6gz9EoQ3sCNu7514GEghZurrktCMiH",
                  "method":"ont",
                  "methodSpecificId":"AN5g6gz9EoQ3sCNu7514GEghZurrktCMiH",
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
            id: 'did:ont:AN5g6gz9EoQ3sCNu7514GEghZurrktCMiH#keys-1',
            kty: KTYS.EC,
            alg: ALGORITHMS.ES256,
            format: KEY_FORMATS.HEX,
            publicKey: '023b041dfc2d00a9846d291dd4bad3f32b8c13a6ad8dc2e97fd711888ed7818c66'
         }
      ]
   },
   {
      method: 'did:sov',
      did: 'did:sov:CYQLsccvwhMTowprMjGjQ6',
      resolverReturn: {
         "didDocument":{
            "@context":"https://www.w3.org/2019/did/v1",
            "id":"did:sov:CYQLsccvwhMTowprMjGjQ6",
            "service":[
               {
                  "type":"custom",
                  "serviceEndpoint":"https://notary.ownyourdata.eu/?hash=fef73e27304f4f9c17655f1c598b75237664aff67e48a50edc51505a742985cf"
               }
            ],
            "authentication":[
               {
                  "type":"Ed25519SignatureAuthentication2018",
                  "publicKey":[
                     "did:sov:CYQLsccvwhMTowprMjGjQ6#key-1"
                  ]
               }
            ],
            "publicKey":[
               {
                  "id":"did:sov:CYQLsccvwhMTowprMjGjQ6#key-1",
                  "type":"Ed25519VerificationKey2018",
                  "publicKeyBase58":"CLFRfp2wa3ifbsVvdq52WcpEy7aujactsoqQgxkz7ZKR"
               }
            ]
         },
         "content":null,
         "contentType":null,
         "resolverMetadata":{
            "duration":800,
            "identifier":"did:sov:CYQLsccvwhMTowprMjGjQ6",
            "driverId":"driver-universalresolver/driver-did-sov",
            "didUrl":{
               "didUrlString":"did:sov:CYQLsccvwhMTowprMjGjQ6",
               "did":{
                  "didString":"did:sov:CYQLsccvwhMTowprMjGjQ6",
                  "method":"sov",
                  "methodSpecificId":"CYQLsccvwhMTowprMjGjQ6",
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
            "network":"_",
            "poolVersion":2,
            "nymResponse":{
               "op":"REPLY",
               "result":{
                  "type":"105",
                  "identifier":"9gk8V5BsjLze9a7BSNXGpx",
                  "dest":"CYQLsccvwhMTowprMjGjQ6",
                  "txnTime":1.546205245E9,
                  "reqId":1.59550447202375245E18,
                  "data":"{\"dest\":\"CYQLsccvwhMTowprMjGjQ6\",\"identifier\":\"DjxRxnL4gXsncbH8jM8ySM\",\"role\":null,\"seqNo\":6296,\"txnTime\":1546205245,\"verkey\":\"CLFRfp2wa3ifbsVvdq52WcpEy7aujactsoqQgxkz7ZKR\"}",
                  "state_proof":{
                     "multi_signature":{
                        "signature":"RH1sUpnJmh4xEoRNrcSukRLq19tACbMuk1Ai6g8RufsyqdCUkoKHJnrbCGTq9yZmXNU61fr4afiqdRc7Bos58H1SJoxuxoxEDpkjHdCQi7fDBzm1LBkB6ReHLTDV7wc9UGHCfqKqzW1qP2AseTYN2N4PLaygEsJy6gX3TQg9E4Mtbq",
                        "participants":[
                           "findentity",
                           "esatus_AG",
                           "ServerVS",
                           "VeridiumIDC",
                           "TNO",
                           "Stuard",
                           "icenode",
                           "prosovitor",
                           "atbsovrin",
                           "OASFCU",
                           "BIGAWSUSEAST1-001",
                           "royal_sovrin",
                           "DustStorm",
                           "pcValidator01"
                        ],
                        "value":{
                           "state_root_hash":"4C2QLTxvPQHCoX3d6hwkw5WB1eX1mSxTiYPFC6dYY51h",
                           "timestamp":1.595504422E9,
                           "pool_state_root_hash":"3gH1k15mjg6oS16x2wnzCPYR8rMaGv6UfpisdQ3VN3Qm",
                           "ledger_id":1.0,
                           "txn_root_hash":"GCeYofyoUqcHGpsT6uwJiW7UyLCyViStqMLbbZPhUmG9"
                        }
                     },
                     "proof_nodes":"+QR++LSgICY2RxHPDlgZ+vBIFq19wQ00JMhUypBKS15znep9R2+4kfiPuI17ImlkZW50aWZpZXIiOiJEanhSeG5MNGdYc25jYkg4ak04eVNNIiwicm9sZSI6bnVsbCwic2VxTm8iOjYyOTYsInR4blRpbWUiOjE1NDYyMDUyNDUsInZlcmtleSI6IkNMRlJmcDJ3YTNpZmJzVnZkcTUyV2NwRXk3YXVqYWN0c29xUWd4a3o3WktSIn35AbGggP7buSs3E/wkkcdwXO5u/WSF3/vdarXSj+eyHsnM9zWAoFgOkohDEQIBNIugNcujidIFjYNqoiPgPevCRU622DlTgKDNWy4bBpyjV0ROZXmoUBfrj8N4bWPbB7eiJO4pHokGHKAfn9vZrAefiuQk2cVFcXs71VNERW+dZrjTflm6jhwfEqDuk8K0AR8uR1yJq4EVijsCqLtk8GmYattnwYadG+vvS6C4l/PHo1eH0/2028+svY8byGEg16v1f+jX+Fj3mrfMRoCg0SzpTlMfWi+unQAmwh3ro8WFlF+yZLw0lnfH5z3wDcigtvQ0QzkVkQSnq7EO8O02SvUDKEluI3clQVOyi0wgXMugMOktTI6iXKVCOgvYNR6xGq7G+7uUQC7GI8lRVbo0x92gsnlvAo7MstJKeXghpoNIAX/gj0mF9OyTcg6vqOXpIFegzh+pgdKGHj1ZIpnXdBfmloRYS/AbyZZy5Wdf6xb5fSqgd3lKxIAVaaYrJHEMuTAbcgnLQlUupu1BJLiM3KvR8YGgjrrzjHURTbvVJb0U43iVcPvfLuRnwKwxtrXvwOZlSuiA+QIRoMNdK2Bt2ymQWeSQDkyQvoceJehUFblV0gZWIkY/R6cAoLgmcWXhRQEmsBJ6b5GmgCdmS3S2iuKok8aXn3hGpQAvoEuolefWO8DaJ99yxVYJrJarolKZmOt7Zf06Ed5s/yZpoP/cdd+t7Jd0BwC5VJbUFv2OjtfVtPDUe4D0/DeFeO4HoJaQxIX0ne5a0IIqlj7JOK78YeRUr80K1JC3uIlWmCK0oEvCoa8TMAonjFTZKw+Nss214b8fS0r89eqlfHRqk+tboCTgxArhoel1KCDYOxTJXo/zLk5iMPH3ElJkgJVo5quKoJupF1jWeOiihkbyKXaHvgs9zgibx2zkv3zwgXTa4Gu2oD/EZlrZkfTokCZyKivO9S14pBNPdQg4C46rURlFJLGcoJeh/RRkdoHVGBRzhEgraS0Pp/xNhbWb4duOKPUh3z87oAE74Na/TPr9p9l5hODVUkvdLgPSAlmInHyX8rDA8GDvoGwxkqS/Ce/4iisGPxCZQOM9zFT2EELIGEB9ks5hqxn5oAW0fixeuP/4aGo8lyZ0YBEyH5axUjnA7imVDRmgIrWYoM+nl5j8M3+LWTIZ4FMqrshZbMrbCiZHehq16Pq7SuVPoDzoxDIAOnL2cYn6B7sLcxxwXH/DHhCNclbLdmjS1DmjoBilUCwzxla98T8CUnSu389hZZbzE4p+STmXmbiMqQl1gA==",
                     "root_hash":"4C2QLTxvPQHCoX3d6hwkw5WB1eX1mSxTiYPFC6dYY51h"
                  },
                  "seqNo":6296.0
               }
            },
            "attrResponse":{
               "op":"REPLY",
               "result":{
                  "type":"104",
                  "identifier":"9gk8V5BsjLze9a7BSNXGpx",
                  "dest":"CYQLsccvwhMTowprMjGjQ6",
                  "raw":"endpoint",
                  "reqId":1.59550447265994624E18,
                  "data":"{\"endpoint\":{\"custom\":\"https://notary.ownyourdata.eu/?hash=fef73e27304f4f9c17655f1c598b75237664aff67e48a50edc51505a742985cf\"}}",
                  "state_proof":{
                     "multi_signature":{
                        "signature":"RH1sUpnJmh4xEoRNrcSukRLq19tACbMuk1Ai6g8RufsyqdCUkoKHJnrbCGTq9yZmXNU61fr4afiqdRc7Bos58H1SJoxuxoxEDpkjHdCQi7fDBzm1LBkB6ReHLTDV7wc9UGHCfqKqzW1qP2AseTYN2N4PLaygEsJy6gX3TQg9E4Mtbq",
                        "participants":[
                           "findentity",
                           "esatus_AG",
                           "ServerVS",
                           "VeridiumIDC",
                           "TNO",
                           "Stuard",
                           "icenode",
                           "prosovitor",
                           "atbsovrin",
                           "OASFCU",
                           "BIGAWSUSEAST1-001",
                           "royal_sovrin",
                           "DustStorm",
                           "pcValidator01"
                        ],
                        "value":{
                           "state_root_hash":"4C2QLTxvPQHCoX3d6hwkw5WB1eX1mSxTiYPFC6dYY51h",
                           "timestamp":1.595504422E9,
                           "pool_state_root_hash":"3gH1k15mjg6oS16x2wnzCPYR8rMaGv6UfpisdQ3VN3Qm",
                           "ledger_id":1.0,
                           "txn_root_hash":"GCeYofyoUqcHGpsT6uwJiW7UyLCyViStqMLbbZPhUmG9"
                        }
                     },
                     "proof_nodes":"+QVX+QHRoAHFhmhI1aNGmtfoo1nSOkf+CA+TUOojL4IO7L3JM+u1oNiz/vcpCjD07H8JLHncrs/GHz7c2nozKSqe8dGLVVaCoO9H3bBZ06VAKnOpQJs8wlq/Fgk0S6yIUDb0IucLIkYkoHNvUJdFJqjQLokPF05oLkScsmLnu5KCqgvpBgFdti44oC4OittchumjtIqgwy/fYrGgiPe+IB8kEVS9dNRWcxYBoJ2PEtF5T5Z4fvlJbVRv7chZlFrDdVzhQtmNc0KS8UD3oHyJwKX3A6F9lAwBZ3g3WaI1B/mDWSXvHNszuosplHQAoNeEdMiX3woQlS9fTHZ3RuXFOgGK9zEHQSxNCv54UO2coHZnLGmRUb+jObH5UFwNXDTMCqjq6ciudkxM/ULsCGCTgKD95+EORNtxShxneLwPEqJuXjwwL5wPGMhcxdDPx2dALqAolNqQexyfRPYSvqHN4BkokLG0cX1E3odikzPKgNsw8aCwMrPRxnvvijuZVeUHoQK3fPh9PTx7CWTNlPZN2Snh9qCzxhuZRbnMy6L3ohf+PxPEX5/0chSNk+FA+PUkQVbCWKD9uYlqAXwPn4UiA8gV28PBE/gIeIckrNYRqzUJBwDlc4CA+Me4WCBRTHNjY3Z3aE1Ub3dwck1qR2pRNjoxOmI2YmY3YmM4ZDk2ZjNlYTlkMTMyYzgzYjNkYThlNzc2MGU0MjAxMzg0ODU2NTczNzJkYjRkNmE5ODFkM2ZkOWW4a/hpuGd7ImxzbiI6NDAyNzgsImx1dCI6MTU2MDcwNzg1MywidmFsIjoiNmFhZTJkOTEyNjQ5Yjk5MjFhNzhmZWMwMDc5MzhiMTliOWE3Mjk2Zjg4OTQ5ZWM2MTZlMWE1YmQ0OTZhOTUwNCJ9+FGAgICAgICAoDOIXoo4TUqTLzWJ/BwCmXMV4paL6Y2QEmzXKlWVaT7JgKDqCmcETD5ekpUIjzSRydwHTxI+k/MuCZoCD+gkOeGN+oCAgICAgID4UYCAgICAoH3Dl/zX9WefhLzRV62tyxlfxsUAT7KtWR/6n3bDMTIogICgfY1lX9Fz63p6aADXTqBaPAbyvttLwjOPXUI2iIgIzCqAgICAgICAgPkCEaDDXStgbdspkFnkkA5MkL6HHiXoVBW5VdIGViJGP0enAKC4JnFl4UUBJrASem+RpoAnZkt0toriqJPGl594RqUAL6BLqJXn1jvA2iffcsVWCayWq6JSmZjre2X9OhHebP8maaD/3HXfreyXdAcAuVSW1Bb9jo7X1bTw1HuA9Pw3hXjuB6CWkMSF9J3uWtCCKpY+yTiu/GHkVK/NCtSQt7iJVpgitKBLwqGvEzAKJ4xU2SsPjbLNteG/H0tK/PXqpXx0apPrW6Ak4MQK4aHpdSgg2DsUyV6P8y5OYjDx9xJSZICVaOariqCbqRdY1njoooZG8il2h74LPc4Im8ds5L988IF02uBrtqA/xGZa2ZH06JAmciorzvUteKQTT3UIOAuOq1EZRSSxnKCXof0UZHaB1RgUc4RIK2ktD6f8TYW1m+Hbjij1Id8/O6ABO+DWv0z6/afZeYTg1VJL3S4D0gJZiJx8l/KwwPBg76BsMZKkvwnv+IorBj8QmUDjPcxU9hBCyBhAfZLOYasZ+aAFtH4sXrj/+GhqPJcmdGARMh+WsVI5wO4plQ0ZoCK1mKDPp5eY/DN/i1kyGeBTKq7IWWzK2womR3oatej6u0rlT6A86MQyADpy9nGJ+ge7C3MccFx/wx4QjXJWy3Zo0tQ5o6AYpVAsM8ZWvfE/AlJ0rt/PYWWW8xOKfkk5l5m4jKkJdYA=",
                     "root_hash":"4C2QLTxvPQHCoX3d6hwkw5WB1eX1mSxTiYPFC6dYY51h"
                  },
                  "seqNo":40278.0,
                  "txnTime":1.560707853E9
               }
            }
         }
      },
      keys: [
         {
            id: 'did:sov:CYQLsccvwhMTowprMjGjQ6#key-1',
            kty: KTYS.OKP,
            alg: ALGORITHMS.EdDSA,
            format: KEY_FORMATS.BASE58,
            publicKey: 'CLFRfp2wa3ifbsVvdq52WcpEy7aujactsoqQgxkz7ZKR'
         }
      ]
   },
   {
      method: 'did:v1',
      did: 'did:v1:test:nym:z6MkgF4uJbLMoUin2uKaBf4Jb1F7SHzuALE8Ldq8FPPpHE9t',
      resolverReturn: {
         "didDocument":{
            "@context":[
               "https://w3id.org/did/v0.11",
               "https://w3id.org/veres-one/v1"
            ],
            "id":"did:v1:test:nym:z6MkgF4uJbLMoUin2uKaBf4Jb1F7SHzuALE8Ldq8FPPpHE9t",
            "assertionMethod":[
               {
                  "id":"did:v1:test:nym:z6MkgF4uJbLMoUin2uKaBf4Jb1F7SHzuALE8Ldq8FPPpHE9t#z6Mksn2L6yxeZBrALghomUsxwik7yZpxPLiJvBCgP8mK3ALm",
                  "type":"Ed25519VerificationKey2018",
                  "controller":"did:v1:test:nym:z6MkgF4uJbLMoUin2uKaBf4Jb1F7SHzuALE8Ldq8FPPpHE9t",
                  "publicKeyBase58":"EKmHWjiDDeMhEBs75uv86dC89zZ6yTTxEAHkYroJ7wZP"
               }
            ],
            "authentication":[
               {
                  "id":"did:v1:test:nym:z6MkgF4uJbLMoUin2uKaBf4Jb1F7SHzuALE8Ldq8FPPpHE9t#z6Mkq76ZBzJJjUQCXB2g8RuKSpLji6ssD3v2jj83wifuR56y",
                  "type":"Ed25519VerificationKey2018",
                  "controller":"did:v1:test:nym:z6MkgF4uJbLMoUin2uKaBf4Jb1F7SHzuALE8Ldq8FPPpHE9t",
                  "publicKeyBase58":"BeqWbk3sPvujQgBySrwUbinjtXc1oAfg3iD87ShtVrKb"
               }
            ],
            "capabilityDelegation":[
               {
                  "id":"did:v1:test:nym:z6MkgF4uJbLMoUin2uKaBf4Jb1F7SHzuALE8Ldq8FPPpHE9t#z6Mkg8GSGyco8vQaiUCHymt7UVACDcq8Mbs2sS97W42b2YAg",
                  "type":"Ed25519VerificationKey2018",
                  "controller":"did:v1:test:nym:z6MkgF4uJbLMoUin2uKaBf4Jb1F7SHzuALE8Ldq8FPPpHE9t",
                  "publicKeyBase58":"2g1PgjNMoNv7byMbJCvGdPcCQ3ZGwicgBREBfn4a7KPJ"
               }
            ],
            "capabilityInvocation":[
               {
                  "id":"did:v1:test:nym:z6MkgF4uJbLMoUin2uKaBf4Jb1F7SHzuALE8Ldq8FPPpHE9t#z6MkgF4uJbLMoUin2uKaBf4Jb1F7SHzuALE8Ldq8FPPpHE9t",
                  "type":"Ed25519VerificationKey2018",
                  "controller":"did:v1:test:nym:z6MkgF4uJbLMoUin2uKaBf4Jb1F7SHzuALE8Ldq8FPPpHE9t",
                  "publicKeyBase58":"2noriM5vTwEJvQUsW66Tjuh7cij3kSymecvCR7RoN1NW"
               }
            ]
         },
         "content":null,
         "contentType":null,
         "resolverMetadata":{
            "duration":1022,
            "identifier":"did:v1:test:nym:z6MkgF4uJbLMoUin2uKaBf4Jb1F7SHzuALE8Ldq8FPPpHE9t",
            "driverId":"driver-veresone/uni-resolver-did-v1-driver-5",
            "didUrl":{
               "didUrlString":"did:v1:test:nym:z6MkgF4uJbLMoUin2uKaBf4Jb1F7SHzuALE8Ldq8FPPpHE9t",
               "did":{
                  "didString":"did:v1:test:nym:z6MkgF4uJbLMoUin2uKaBf4Jb1F7SHzuALE8Ldq8FPPpHE9t",
                  "method":"v1",
                  "methodSpecificId":"test:nym:z6MkgF4uJbLMoUin2uKaBf4Jb1F7SHzuALE8Ldq8FPPpHE9t",
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
            id: 'did:v1:test:nym:z6MkgF4uJbLMoUin2uKaBf4Jb1F7SHzuALE8Ldq8FPPpHE9t#z6Mkq76ZBzJJjUQCXB2g8RuKSpLji6ssD3v2jj83wifuR56y',
            kty: KTYS.OKP,
            alg: ALGORITHMS.EdDSA,
            format: KEY_FORMATS.BASE58,
            publicKey: 'BeqWbk3sPvujQgBySrwUbinjtXc1oAfg3iD87ShtVrKb'
         }
      ]
   }
]

export const invalidDID = 'did:ethr:0xB07Ead9717b44B6cF439c474362b9C0877CBBF8';