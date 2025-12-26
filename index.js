require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const axios = require('axios');

const app = express();

// Lấy các giá trị từ .env
const LARK_DOMAIN = process.env.Lark_Domain || 'https://open.larksuite.com/';
const APP_ID = process.env.App_ID;
const APP_SECRET = process.env.App_Secret;
const VERIFICATION_TOKEN = process.env.Verification_Token;
const ENCRYPT_KEY = process.env.Encrypt_Key.trim();
const AI_KEY = process.env.AI_Key.trim();

// Hàm xác thực chữ ký Lark bằng SHA256
function verifySignature(timestamp, nonce, body, signature) {
  try {
    const raw = `${timestamp}${nonce}${ENCRYPT_KEY}${body}`;
    const hash = crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
    const isValid = hash === signature;

    if (!isValid) {
      console.warn("[verifySignature] ❌ Signature mismatch");
      console.warn("  ↳ Calculated:", hash);
      console.warn("  ↳ Received:  ", signature);
    }

    return isValid;
  } catch (err) {
    console.error("Signature verify error:", err);
    return false;
  }
}

// Hàm giải mã message (AES-256-CBC)
function decryptMessage(encrypt) {
  try {
    const key = Buffer.from(ENCRYPT_KEY, 'utf-8');
    const aesKey = crypto.createHash('sha256').update(key).digest();
    const data = Buffer.from(encrypt, 'base64');
    const iv = data.slice(0, 16);
    const encryptedText = data.slice(16);

    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return JSON.parse(decrypted.toString());
  } catch (err) {
    console.error("Decrypt error:", err.message);
    return null;
  }
}

// -------------------- WEBHOOK --------------------
app.post('/lark-webhook', express.raw({ type: '*/*' }), async (req, res) => {
  const rawBody = req.body.toString('utf8');
  const signature = req.headers['x-lark-signature'];
  const timestamp = req.headers['x-lark-request-timestamp'];
  const nonce = req.headers['x-lark-request-nonce'];

  console.log("All headers:", req.headers);
  console.log("Raw body:", rawBody);

  if (!timestamp || !nonce || !signature) {
    console.log("Missing required headers for signature verification");
    return res.status(400).send('Missing headers');
  }

  // Kiểm tra chữ ký
  let isVerified = true;
  if (rawBody.includes('"encrypt"')) {
    isVerified = verifySignature(timestamp, nonce, rawBody, signature);
  }

  if (!isVerified) {
    console.error("[Webhook] ❌ Signature verification failed.");
    return res.status(401).send('Invalid signature');
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch (err) {
    console.warn("[Webhook] ❌ Cannot parse JSON payload:", err.message);
    return res.sendStatus(400);
  }

  // Giải mã nếu cần
  let decrypted = payload;
  if (payload?.encrypt) {
    try {
      decrypted = decryptMessage(payload.encrypt);
    } catch (err) {
      console.error("[Webhook] ❌ decryptMessage error:", err.message);
      return res.json({ code: 0 });
    }
  }

  console.log("Decrypted payload:", decrypted);

  // Kiểm tra thử thách
  if (decrypted?.challenge) {
    console.log("[Webhook] 🔑 Verification challenge received");
    return res.json({ challenge: decrypted.challenge });
  }

  // Kiểm tra token xác thực
  if (decrypted.token && decrypted.token !== VERIFICATION_TOKEN) {
    console.log("Invalid token:", decrypted.token);
    return res.status(401).send('Invalid token');
  }

  const userMessage = decrypted.event?.text?.content || '';
  console.log('User message:', userMessage);

  // Gửi yêu cầu đến OpenRouter API
  try {
    const response = await axios.post(
      'https://openrouter.ai/api/v1/chat/completions',
      {
        model: 'gpt-4o-mini',
        messages: [{ role: 'user', content: userMessage }],
      },
      { headers: { 'Authorization': `Bearer ${AI_KEY}` } }
    );

    const aiReply = response.data.choices[0].message.content;
    console.log('AI reply:', aiReply);

    // Trả về phản hồi hợp lệ
    res.json({
      status: "success",
      msg_type: "text",
      content: { text: aiReply }
    });

  } catch (err) {
    console.error('OpenRouter API error:', err.message);
    return res.status(500).json({ status: "error", message: "Invalid response from OpenRouter API" });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
