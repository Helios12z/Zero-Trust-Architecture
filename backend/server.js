const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Request tracer middleware
app.use((req, res, next) => {
  const now = new Date().toISOString();
  console.log(`[${now}] 📥 [Backend] Received ${req.method} request for '${req.path}'`);
  console.log(`[${now}] 📥 [Backend] Source IP: ${req.ip}`);
  console.log(`[${now}] 📥 [Backend] Request Headers:`, JSON.stringify(req.headers, null, 2));
  next();
});

// Sensitive target endpoint
app.get('/api/resource', (req, res) => {
  const now = new Date().toISOString();
  console.log(`[${now}] 🔑 [Backend] ACCESS SUCCESSFUL: Serving 'TOP_SECRET_FINANCE_REPORT' to proxy client`);
  
  res.status(200).json({
    status: "success",
    data: "TOP_SECRET_FINANCE_REPORT",
    confidentiality: "CLASSIFIED",
    timestamp: now,
    server_node: "zta-backend-v1"
  });
});

// Fallback endpoint
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found on backend" });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 [Backend] Target API successfully listening internally on port ${PORT}...`);
});
