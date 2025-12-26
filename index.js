require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const axios = require('axios');

const app = express();

// Giữ raw body để debug
app.use(bodyParser.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString('utf8'); // đảm bảo utf8
  }
}));

// Thông tin từ .env
const APP_ID = process.env.App_ID;
const APP_SECRET = process.env.App_Secret;
const VERIFICATION_TOKEN = process.env.Verification_Token;
const ENCRYPT_KEY = process.env.Encrypt_Key.trim();
const AI_KEY = process.env.AI_Key.trim();
const LARK_DOMAIN = process.env.Lark_Domain?.trim() || 'https://open.larksuite.com/';

// Hàm xác thực signature Lark bằng HMAC SHA256
function verifySignature(timestamp, nonce, body, signature) {
  try {
    const key = Buffer.from(ENCRYPT_KEY, 'base64');
    const text = `${timestamp}\n${nonce}\n${body}\n`;
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(text);
    const hash = hmac.digest('base64');
    return hash === signature;
  } catch (err) {
    console.error("Signature verify error:", err);
    return false;
  }
}

// Hàm giải mã message (AES-128-ECB)
function decryptMessage(encrypt) {
  try {
    const key = Buffer.from(ENCRYPT_KEY, 'base64').slice(0, 16);
    const decipher = crypto.createDecipheriv('aes-128-ecb', key, null);
    decipher.setAutoPadding(true);
    let decrypted = decipher.update(encrypt, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
  } catch (err) {
    console.error("Decrypt error:", err.message);
    return null;
  }
}

// Webhook xử lý sự kiện Lark
app.post('/lark-webhook', async (req, res) => {
  const timestamp = req.get('x-lark-request-timestamp');
  const nonce = req.get('x-lark-request-nonce');
  const signature = req.get('x-lark-signature');

  console.log("Headers received:");
  console.log({ timestamp, nonce, signature });
  console.log("=== Incoming raw body ===");
  console.log(req.rawBody);

  if (!timestamp || !nonce || !signature) {
    console.log("Missing required headers for signature verification");
    return res.status(400).send('Missing headers');
  }

  // Xác thực chữ ký
  if (!verifySignature(timestamp, nonce, req.rawBody, signature)) {
    console.log("Invalid signature!");
    return res.status(401).send('Invalid signature');
  }

  const encrypt = req.body.encrypt;
  if (!encrypt) {
    console.log("No encrypt field found");
    return res.status(400).send('No encrypt field');
  }

  const decrypted = decryptMessage(encrypt);
  if (!decrypted) {
    return res.status(400).send('Decrypt failed');
  }

  console.log("=== Decrypted payload ===");
  console.log(decrypted);

  if (decrypted.type === 'url_verification') {
    // Trả về challenge khi verify url
    return res.json({ challenge: decrypted.challenge });
  }

  if (decrypted.token !== VERIFICATION_TOKEN) {
    console.log("Invalid token:", decrypted.token);
    return res.status(401).send('Invalid token');
  }

  const userMessage = decrypted.event?.text?.content || '';
  console.log("User message:", userMessage);

  try {
    const response = await axios.post(
      'https://openrouter.ai/api/v1/chat/completions',
      {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: userMessage }]
      },
      {
        headers: { 'Authorization': `Bearer ${AI_KEY}` }
      }
    );

    const aiReply = response.data.choices[0].message.content;
    console.log("AI reply:", aiReply);

    res.json({
      status: "success",
      msg_type: "text",
      content: { text: aiReply }
    });

  } catch (err) {
    console.error("OpenRouter API error:", err.message);
    res.status(500).json({ status: "error", message: "OpenRouter API error" });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
