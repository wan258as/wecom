import express from "express";
import dotenv from "dotenv";
import { parseXmlToObj, buildXml } from "./xml.js";
import { WeComCrypto } from "./wecomCrypto.js";

dotenv.config();


const {
  WECOM_CORP_ID,
  WECOM_TOKEN,
  WECOM_AES_KEY,
  PORT = "3000",
  AUTO_REPLY_TEXT = "false"
} = process.env;

if (!WECOM_CORP_ID || !WECOM_TOKEN || !WECOM_AES_KEY) {
  console.error("Missing env vars. Please set WECOM_CORP_ID, WECOM_TOKEN, WECOM_AES_KEY");
  process.exit(1);
}

const cryptoHelper = new WeComCrypto({
  corpId: WECOM_CORP_ID,
  token: WECOM_TOKEN,
  encodingAesKey: WECOM_AES_KEY
});

const app = express();

process.on("uncaughtException", (err) => {
  console.error("UNCAUGHT EXCEPTION:", err);
});

process.on("unhandledRejection", (err) => {
  console.error("UNHANDLED REJECTION:", err);
});

// WeCom sends XML
// WeCom sends XML (often Content-Type: text/xml or application/xml)
app.use(express.text({ type: ["text/xml", "application/xml"], limit: "2mb" }));
app.get("/health", (req, res) => {
  res.status(200).send("ok");
});

/**
 * Callback endpoint (set this URL in WeCom console):
 *   https://YOUR_DOMAIN/wecom/callback
 *
 * WeCom URL verification uses GET with:
 *   msg_signature, timestamp, nonce, echostr
 */
app.get("/wecom/callback", (req, res) => {
  try {
    const { msg_signature, timestamp, nonce, echostr } = req.query;

    // ✅ 空GET / 缺参数：也返回200，方便连通性测试 & 避免WeCom误判
    if (!msg_signature || !timestamp || !nonce || !echostr) {
      return res.status(200).send("ok");
    }

app.get("/", (req, res) => {
  res.status(200).send("ok");
});

app.get("/health", (req, res) => {
  res.status(200).send("ok");
});
   
    // verify signature and decrypt echostr
    const plainEcho = cryptoHelper.verifyUrl({
      msgSignature: String(msg_signature),
      timestamp: String(timestamp),
      nonce: String(nonce),
      echoStr: String(echostr),
    });

    // IMPORTANT: return plaintext exactly
    return res.status(200).send(plainEcho);
  } catch (err) {
    console.error("GET /wecom/callback error:", err?.message || err);
    // ✅ 建议这里也返回200，避免企业微信把“异常”当成“连不上”
    return res.status(200).send("fail");
  }
});


/**
 * WeCom message/event push uses POST:
 * Query: msg_signature, timestamp, nonce
 * Body: <xml><Encrypt>...</Encrypt></xml>
 */
app.post("/wecom/callback", async (req, res) => {
  try {
    const { msg_signature, timestamp, nonce } = req.query;

    if (!msg_signature || !timestamp || !nonce) {
      return res.status(400).send("Missing query params");
    }

    const rawXml = req.body || "";
    if (!rawXml.trim()) return res.status(400).send("Empty body");

    const outer = parseXmlToObj(rawXml);
    const encrypt = outer?.xml?.Encrypt;
    if (!encrypt) return res.status(400).send("Missing Encrypt in XML body");

    // Verify + decrypt
    const decryptedXml = cryptoHelper.decryptMessage({
      msgSignature: String(msg_signature),
      timestamp: String(timestamp),
      nonce: String(nonce),
      encrypt: String(encrypt)
    });

    console.log("\n==== Decrypted WeCom XML ====\n", decryptedXml, "\n============================\n");
app.post("/wecom/callback", (req, res) => {
  try {
    console.log("POST query:", req.query);
    console.log("POST body:", req.body);

    // 先简单返回 success，防止企业微信重试
    return res.status(200).send("success");
  } catch (err) {
    console.error(err);
    return res.status(200).send("success");
  }
});
    // Parse decrypted message for optional auto-reply
    const inner = parseXmlToObj(decryptedXml);
    const msg = inner?.xml || {};
    const msgType = msg.MsgType;

    // Default: return "success" quickly (recommended)
    const shouldAutoReply = String(AUTO_REPLY_TEXT).toLowerCase() === "true";

    if (!shouldAutoReply || msgType !== "text") {
      return res.status(200).send("success");
    }

    // --- Optional auto-reply for text messages ---
    const toUser = msg.FromUserName; // the sender
    const fromUser = msg.ToUserName; // your corp/app/service
    const content = msg.Content || "";

    const replyText = `收到：${content}`;

    const replyPlainXml = buildXml({
      ToUserName: toUser,
      FromUserName: fromUser,
      CreateTime: Math.floor(Date.now() / 1000),
      MsgType: "text",
      Content: replyText
    });

    // Encrypt reply and sign
    const encryptedReply = cryptoHelper.encryptMessage({
      replyXml: replyPlainXml,
      nonce: String(nonce),
      timestamp: String(timestamp)
    });

    return res.status(200).type("application/xml").send(encryptedReply);
  } catch (err) {
    console.error("POST /wecom/callback error:", err?.message || err);
    return res.status(500).send("fail");
  }
});




app.listen(Number(PORT), "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
server.on("error", (err) => {
  console.error("HTTP server error:", err);
});
