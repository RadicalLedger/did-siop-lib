import { ECKey } from '../src/core/JWKUtils';
import { encrypt, decrypt } from '../src/core/JWE';

let privateKey = ECKey.fromPrivateKey(
    {
        "kty": "EC",
        "d": "qY02md1Z-mx7Bm99qjqaESCCE8PMpq8VWl3Kla9NexI",
        "use": "sig",
        "crv": "secp256k1",
        "kid": "key_1",
        "x": "fGyWU7xBqgKtBsVjAesZUC1PZhgdpZiV26DGHZ4BV5g",
        "y": "eBxt2i2koNKYqNNI7hTLU0qpsBRKZifw4kaU2RdntQk",
        "alg": "ES256K"
    }
)
let publicKey = ECKey.fromPublicKey(
    {
        "kty": "EC",
        "use": "sig",
        "crv": "secp256k1",
        "kid": "key_1",
        "x": "fGyWU7xBqgKtBsVjAesZUC1PZhgdpZiV26DGHZ4BV5g",
        "y": "eBxt2i2koNKYqNNI7hTLU0qpsBRKZifw4kaU2RdntQk",
        "alg": "ES256K"
    }
)

describe('JWE Test', function(){
    test('Test encryption', ()=>{
        let { secret, epk } = encrypt('awd', publicKey);
        console.log(secret);
        let generatedKey = decrypt('awd', epk, privateKey);
        console.log(generatedKey);
    })
})