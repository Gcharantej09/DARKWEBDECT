const express = require('express');
const router = express.Router();
const { evaluateUrl } = require('../services/riskEngine');

router.post('/evaluate', async (req, res) => {
  const { url, userId, context } = req.body;
  if (!url) return res.status(400).json({ error: 'url is required' });

  try {
    const result = await evaluateUrl(url, userId, context);
    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err?.message || 'Internal error' });
  }
});

module.exports = router;