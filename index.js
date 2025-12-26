require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const { Webhook } = require('@larksuiteoapi/node-sdk');

const app = express();
app.use(bodyParser.json());

// Khởi tạo SDK Lark
const webhook = new Webhook({
  appId: process.env.App_ID,
  appSecret: process.env.App_Secret,
  encryptKey: process.env.Encrypt_Key,
  verificationToken: process.env.Verification_Token
});

// Webhook Lark Bot
app.post('/lark-webhook', async (req, res) => {
  try {
    // SDK tự giải mã payload
    const event = webhook.parseEvent(req.body);
    console.log("Decrypted event:", event);

    // Xử lý URL verification
    if (event.type === 'url_verification') {
      return res.json({ challenge: event.challenge });
    }

    // Lấy message từ user
    const userMessage = event.event?.text?.content || '';
    console.log("User message:", userMessage);

    // Gửi request tới OpenRouter
    const response = await axios.post(
      'https://openrouter.ai/api/v1/chat/completions',
      {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: userMessage }]
      },
      {
        headers: { 'Authorization': `Bearer ${process.env.AI_Key}` }
      }
    );

    const aiReply = response.data.choices[0].message.content;
    console.log("AI reply:", aiReply);

    // Trả về Lark theo chuẩn JSON
    res.json({
      status: "success",
      msg_type: "text",
      content: { text: aiReply }
    });

  } catch (err) {
    console.error("Error handling webhook:", err);
    res.status(500).json({ status: "error", message: err.message });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
