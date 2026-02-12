import { XMLParser } from "fast-xml-parser";

const parser = new XMLParser({
  ignoreAttributes: true,
  trimValues: true,
  parseTagValue: false
});

export function parseXmlToObj(xmlStr) {
  return parser.parse(xmlStr);
}

export function buildXml(fields) {
  // Minimal builder for reply XML (text message). Wrap strings in CDATA.
  const cdata = (v) => `<![CDATA[${String(v ?? "")}]]>`;
  return (
    `<xml>` +
    `<ToUserName>${cdata(fields.ToUserName)}</ToUserName>` +
    `<FromUserName>${cdata(fields.FromUserName)}</FromUserName>` +
    `<CreateTime>${Number(fields.CreateTime) || Math.floor(Date.now() / 1000)}</CreateTime>` +
    `<MsgType>${cdata(fields.MsgType)}</MsgType>` +
    `<Content>${cdata(fields.Content)}</Content>` +
    `</xml>`
  );
}
