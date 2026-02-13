import express from "express";
import dotenv from "dotenv";
import OpenAI from "openai";
import { parseXmlToObj } from "./xml.js";
import { WeComCrypto } from "./wecomCrypto.js";

dotenv.config();

const {
  WECOM_CORP_ID,
  WECOM_TOKEN,
  WECOM_AES_KEY,
  WECOM_APP_SECRET,
  WECOM_AGENT_ID = "1000003",
  OPENAI_API_KEY,
  PORT = "3000",
} = process.env;

if (!WECOM_CORP_ID || !WECOM_TOKEN || !WECOM_AES_KEY) {
  console.error("Missing env vars: WECOM_CORP_ID, WECOM_TOKEN, WECOM_AES_KEY");
  process.exit(1);
}
if (!WECOM_APP_SECRET) {
  console.error("Missing env var: WECOM_APP_SECRET (自建应用 secret)");
  process.exit(1);
}
if (!OPENAI_API_KEY) {
  console.error("Missing env var: OPENAI_API_KEY");
  process.exit(1);
}

const cryptoHelper = new WeComCrypto({
  corpId: WECOM_CORP_ID,
  token: WECOM_TOKEN,
  encodingAesKey: WECOM_AES_KEY,
});

const openai = new OpenAI({ apiKey: OPENAI_API_KEY });

const app = express();

// WeCom sends XML (text/xml or application/xml)
app.use(express.text({ type: ["text/xml", "application/xml", "*/*"], limit: "2mb" }));

process.on("uncaughtException", (err) => console.error("UNCAUGHT EXCEPTION:", err));
process.on("unhandledRejection", (err) => console.error("UNHANDLED REJECTION:", err));

app.get("/", (req, res) => res.status(200).send("ok"));
app.get("/health", (req, res) => res.status(200).send("ok"));

/**
 * GET URL verification:
 * /wecom/callback?msg_signature=...&timestamp=...&nonce=...&Missing env var: WECOM_APP_SECRET (自建应用 secret)echostr=...
 */
app.get("/wecom/callback", (req, res) => {
  try {
    const { msg_signature, timestamp, nonce, echostr } = req.query;

    // 允许空 GET 做连通性测试
    if (!msg_signature || !timestamp || !nonce || !echostr) {
      return res.status(200).send("ok");
    }

    const plainEcho = cryptoHelper.verifyUrl({
      msgSignature: String(msg_signature),
      timestamp: String(timestamp),
      nonce: String(nonce),
      echoStr: String(echostr),
    });

    return res.status(200).send(plainEcho);
  } catch (err) {
    console.error("GET /wecom/callback error:", err?.message || err);
    // 别返回 500，避免企业微信当成不可用
    return res.status(200).send("fail");
  }
});

// --------------------- WeCom access_token cache ---------------------
let tokenCache = { token: null, expireAt: 0 };

async function getWecomAccessToken() {
  const now = Date.now();
  if (tokenCache.token && now < tokenCache.expireAt - 60_000) {
    return tokenCache.token;
  }

  const url =
    `https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=${encodeURIComponent(WECOM_CORP_ID)}&corpsecret=${encodeURIComponent(WECOM_APP_SECRET)}`;

  const r = await fetch(url);
  const j = await r.json();

  if (j.errcode !== 0) {
    throw new Error(`gettoken failed: ${j.errcode} ${j.errmsg}`);
  }

  tokenCache.token = j.access_token;
  tokenCache.expireAt = now + (j.expires_in || 7200) * 1000;
  return tokenCache.token;
}

async function sendWecomText(toUser, content) {
  const token = await getWecomAccessToken();
  const url = `https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=${encodeURIComponent(token)}`;

  const body = {
    touser: toUser,
    msgtype: "text",
    agentid: Number(WECOM_AGENT_ID),
    text: { content },
    safe: 0,
  };

  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  const j = await r.json();
  if (j.errcode !== 0) {
    throw new Error(`message/send failed: ${j.errcode} ${j.errmsg}`);
  }
}

// --------------------- POST callback ---------------------
/**
 * POST message push:
 * /wecom/callback?msg_signature=...&timestamp=...&nonce=...
 * body: <xml><Encrypt>...</Encrypt></xml>
 */
app.post("/wecom/callback", async (req, res) => {
  // 先尽量拿到 query / body，即使后面失败也别让企业微信一直重试
  const { msg_signature, timestamp, nonce } = req.query;
  const rawXml = req.body || "";

  try {
    if (!msg_signature || !timestamp || !nonce) {
      return res.status(400).send("Missing query params");
    }
    if (!rawXml.trim()) {
      return res.status(400).send("Empty body");
    }

    const outer = parseXmlToObj(rawXml);
    const encrypt = outer?.xml?.Encrypt;

    // 解密（如果没有 Encrypt，当作明文兼容）
    let decryptedXml = "";
    if (encrypt) {
      decryptedXml = cryptoHelper.decryptMessage({
        msgSignature: String(msg_signature),
        timestamp: String(timestamp),
        nonce: String(nonce),
        encrypt: String(encrypt),
      });
    } else {
      decryptedXml = rawXml;
    }

    const inner = parseXmlToObj(decryptedXml);
    const msg = inner?.xml || {};

    console.log("\n==== Incoming WeCom XML (decrypted/plain) ====\n", decryptedXml, "\n============================================\n");

    // 只处理文本消息
    const msgType = msg.MsgType;
    const fromUser = msg.FromUserName;
    const content = (msg.Content || "").trim();

    // ✅ 立刻 ACK，避免 5 秒超时重试
    res.status(200).send("success");

    // 异步处理（不要 await 卡住回调）
    (async () => {
      try {
        if (msgType !== "text" || !fromUser || !content) return;

        const aiResp = await openai.responses.create({
          model: "gpt-3.5-turbo",
          input: content,
        });

        const reply = (aiResp.output_text || "").trim() || "（我暂时没有生成出回复）";
        const safeReply = reply.length > 1800 ? reply.slice(0, 1800) + "…" : reply;

        await sendWecomText(fromUser, safeReply);
      } catch (e) {
        console.error("Async AI/send error:", e?.message || e);
        try {
          if (fromUser) {
            await sendWecomText(fromUser, "抱歉，我刚刚出了一点问题，稍后再试一次。");
          }
        } catch {}
      }
    })();

    return;
  } catch (err) {
    console.error("POST /wecom/callback error:", err?.message || err);

    // 尽量 ACK，避免企业微信狂重试
    try {
      return res.status(200).send("success");
    } catch {
      return;
    }
  }
});
app.get("/debug-openai", async (req, res) => {
  if (req.query.token !== process.env.DEBUG_TOKEN) {
    return res.status(403).send("Forbidden");
  }

  try {
    const response = await fetch("https://api.openai.com/v1/models", {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`,
      },
    });

    const text = await response.text();
    res.status(response.status).send(text);

  } catch (error) {
    res.status(500).send(String(error));
  }
});

const portNum = Number(PORT || 3000);
app.listen(portNum, "0.0.0.0", () => {
  console.log(`WeCom callback server listening on port ${portNum}`);
});
