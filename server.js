require('dotenv').config();
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

const api = require('./routes/api');

const app = express();
const PORT = process.env.PORT || 3000;

app.disable('x-powered-by');
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));
app.use(cors());
app.use(express.json({ limit: '256kb' }));

app.use('/api', api);

app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((req, res) => res.status(404).json({ error: 'nao encontrado' }));
app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: 'erro interno' });
});

app.listen(PORT, () => {
    console.log('You server rodando na porta ' + PORT);
});
