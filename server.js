// server.js
const express = require('express');
const app = express();

app.get('/', (req, res) => {
  res.send('<h1>Hello from Origin Server</h1>');
});

app.get('/secure', (req, res) => {
  res.send('<h1>Secure Area</h1>');
});

app.listen(3000, () => console.log('Server running on port 3000'));
