const express = require('express');
const serverless = require('serverless-http');

const app = express();

// Middleware
app.use(express.json());

// Your existing routes
app.post('/api/packets', (req, res) => {
  const { packetData } = req.body;
  // Your packet processing logic here
  console.log('Received packet:', packetData);
  res.json({ status: 'Packet stored', data: packetData });
});

app.get('/api/packets', (req, res) => {
  // Return stored packets
  res.json({ packets: [] }); // Add your logic
});

// Export serverless function
module.exports.handler = serverless(app);