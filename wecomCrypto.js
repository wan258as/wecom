import crypto from "crypto";

/**
 * Implements WeCom (企业微信) callback crypto:
 * - Signature: sha1(sort(token, timestamp, nonce, encrypt).join(''))
 * - AES: AES-256-CBC, key is base64(EncodingAESKey + '=')
 * - Plaintext structure: 16 random bytes + 4-byte length + xml + corpId
 * - PKCS7 padding
 */
export class WeComCrypto {
  constructor({ corpId, token, encodingAesKey }) {
    this.corpId = corpId;
    this.token = token;

    if (!encodingAesKey || encodingAesKey.length !== 43) {
      throw new Error("EncodingAESKey must be 43 characters");
    }
    const aesKey = Buffer.from(encodingAesKey + "=", "base64");
    if (aesKey.length !== 32) {
      throw new Error("Invalid EncodingAESKey (decoded AES key not 32 bytes)");
    }
    this.aesKey = aesKey;
    this.iv = aesKey.subarray(0, 16);
  }

  // ---------- Public helpers ----------

  verifyUrl({ msgSignature, timestamp, nonce, echoStr }) {
    // echoStr is encrypted string
    const expected = this.getSignature(timestamp, nonce, echoStr);
    if (expected !== msgSignature) throw new Error("Signature mismatch on URL verification");

    const decrypted = this.decrypt(echoStr);
    // decrypted is plaintext XML-ish "echo" string (not full message xml necessarily)
    // BUT the decrypted payload includes corpId check already in decrypt()
    return decrypted;
  }

  decryptMessage({ msgSignature, timestamp, nonce, encrypt }) {
    const expected = this.getSignature(timestamp, nonce, encrypt);
    if (expected !== msgSignature) throw new Error("Signature mismatch on message");

    return this.decrypt(encrypt);
  }

  encryptMessage({ replyXml, nonce, timestamp }) {
    const encrypt = this.encrypt(replyXml);
    const signature = this.getSignature(timestamp, nonce, encrypt);

    // WeCom expects xml:
    // <xml><Encrypt><![CDATA[...]]></Encrypt><MsgSignature><![CDATA[...]]></MsgSignature>
    // <TimeStamp>...</TimeStamp><Nonce><![CDATA[...]]></Nonce></xml>
    return (
      `<xml>` +
      `<Encrypt><![CDATA[${encrypt}]]></Encrypt>` +
      `<MsgSignature><![CDATA[${signature}]]></MsgSignature>` +
      `<TimeStamp>${timestamp}</TimeStamp>` +
      `<Nonce><![CDATA[${nonce}]]></Nonce>` +
      `</xml>`
    );
  }

  // ---------- Signature ----------

  getSignature(timestamp, nonce, encrypt) {
    const arr = [this.token, String(timestamp), String(nonce), String(encrypt)].sort();
    const sha1 = crypto.createHash("sha1");
    sha1.update(arr.join(""));
    return sha1.digest("hex");
  }

  // ---------- AES decrypt/encrypt core ----------

  decrypt(encryptedBase64) {
    const cipherText = Buffer.from(encryptedBase64, "base64");

    const decipher = crypto.createDecipheriv("aes-256-cbc", this.aesKey, this.iv);
    decipher.setAutoPadding(false);

    const padded = Buffer.concat([decipher.update(cipherText), decipher.final()]);
    const plain = pkcs7Unpad(padded);

    // parse structure: 16 random + 4 bytes len + xml + corpId
    if (plain.length < 20) throw new Error("Decrypted content too short");

    const msgLen = plain.readUInt32BE(16);
    const xmlStart = 20;
    const xmlEnd = xmlStart + msgLen;

    if (xmlEnd > plain.length) throw new Error("Invalid msg length in decrypted content");

    const xmlBuf = plain.subarray(xmlStart, xmlEnd);
    const corpIdBuf = plain.subarray(xmlEnd);

    const corpId = corpIdBuf.toString("utf8");
    if (corpId !== this.corpId) {
      throw new Error("CorpID mismatch in decrypted content");
    }

    return xmlBuf.toString("utf8");
  }

  encrypt(plainXml) {
    const random16 = crypto.randomBytes(16);
    const xmlBuf = Buffer.from(plainXml, "utf8");
    const corpBuf = Buffer.from(this.corpId, "utf8");

    const msgLenBuf = Buffer.alloc(4);
    msgLenBuf.writeUInt32BE(xmlBuf.length, 0);

    const raw = Buffer.concat([random16, msgLenBuf, xmlBuf, corpBuf]);
    const padded = pkcs7Pad(raw);

    const cipher = crypto.createCipheriv("aes-256-cbc", this.aesKey, this.iv);
    cipher.setAutoPadding(false);

    const encrypted = Buffer.concat([cipher.update(padded), cipher.final()]);
    return encrypted.toString("base64");
  }
}

// ---------- PKCS7 padding helpers ----------

function pkcs7Pad(buf) {
  const blockSize = 32;
  const padLen = blockSize - (buf.length % blockSize || blockSize);
  const pad = Buffer.alloc(padLen, padLen);
  return Buffer.concat([buf, pad]);
}

function pkcs7Unpad(buf) {
  const padLen = buf[buf.length - 1];
  if (padLen < 1 || padLen > 32) throw new Error("Invalid PKCS7 padding");
  // verify padding bytes
  for (let i = 0; i < padLen; i++) {
    if (buf[buf.length - 1 - i] !== padLen) throw new Error("Invalid PKCS7 padding bytes");
  }
  return buf.subarray(0, buf.length - padLen);
}
