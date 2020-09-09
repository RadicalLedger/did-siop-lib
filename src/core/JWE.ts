import { Key } from "./JWKUtils";
import base64url from 'base64url';
import { KTYS, KEY_FORMATS, ALGORITHMS } from "./globals";
import { ec as EC } from 'elliptic';
import { createECDH } from 'crypto';
const NodeRSA = require('node-rsa');

export interface JWEHeader{
    alg: string,
    epk: any,
    enc: string,
    kid: string,
}

export interface EncryptionInfo{
    alg: ALGORITHMS;
    kid: string;
    key: string;
    format: KEY_FORMATS;
}

export interface JWTEncryptedObject{
    header: JWEHeader;
    iv: Buffer;
    ciphertext: Buffer;
    auth_tag: Buffer,
}

export const ERRORS = Object.freeze({
    INVALID_JWE: 'Invalid JWE',
});

function decodeJWT(jwe: string): JWTEncryptedObject{
    try {
        let header = JSON.parse(base64url.decode(jwe.split('.')[0]));
        let iv = base64url.toBuffer(jwe.split('.')[2]);
        let ciphertext = base64url.toBuffer(jwe.split('.')[3]);
        let auth_tag = base64url.toBuffer(jwe.split('.')[4]);
    
        return {
            header,
            iv,
            ciphertext,
            auth_tag,
        }
    } catch (err) {
        throw new Error(ERRORS.INVALID_JWE);
    }
}