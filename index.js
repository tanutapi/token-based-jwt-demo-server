const SECRET = 'THIS is a SeCrEt';
const PORT = 3000;
const TOKEN_EXPIRATION = 5 * 60 * 1000;
const REFRESH_TOKEN_EXPIRATION = 60 * 60 * 1000;

const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();


const subjects = {
  'admin': {
    name: 'Tanut',
    surname: 'A.',
    address: 'Bangkok, Thailand',
    email: 'myemail@address.com',
  },
};

const refreshTokens = {};
const clients = {};

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cors());
app.use('/', express.static('public'));

function authToken(req, res, next) {
  if (req.headers.authorization) {
    const token = req.headers['authorization'].replace('Bearer ', '');
    try {
      req.jwt = jwt.verify(token, SECRET);
      next();
    } catch (err) {
      res.status(403).end('Invalid token!');
    }
  } else {
    res.status(403).end('No token provided!');
  }
}

function authClientId(req, res, next) {
  const clientId = req.headers['client-id'];
  if (!clientId || !clients[clientId]) {
    res.status(403).end('Invalid client!');
  } else {
    req.clientId = clientId;
    next();
  }
}

function showRefreshTokensAndClients() {
  console.log('Refresh tokens', refreshTokens);
  console.log('Clients', clients);
}

app.post('/auth/login', function(req, res) {
  const username = req.body.username;
  const password = req.body.password;
  const clientId = req.body.clientId;
  console.log(req.body);
  console.log('login...', username, password, clientId);
  if (
    username && password && 
    clientId &&
    username === 'admin' && password === 'password'
  ) {
    const token = jwt.sign({
      sub: username,
      exp: parseInt((Date.now() + TOKEN_EXPIRATION) / 1000),
      iss: 'token-based-jwt-demo-server',
    }, SECRET);
    const refreshToken = uuidv4();

    if (clients[clientId]) {
      console.log(clients[clientId]);
      delete refreshTokens[clients[clientId]];
    }

    refreshTokens[refreshToken] = {
      sub: username,
      exp: Date.now() + REFRESH_TOKEN_EXPIRATION,
      clientId: clientId,
    };

    clients[clientId] = refreshToken;

    res.json({
      jwt: token,
      refresh: refreshToken,
    });

    showRefreshTokensAndClients();
  } else {
    res.status(400).json({err: 'Invalid username or password'});
  }
});

app.get('/auth/logout', [authToken, authClientId], function(req, res) {
  const refreshToken = clients[req.clientId];
  delete refreshTokens[refreshToken]
  delete clients[req.clientId]
  res.end();
  showRefreshTokensAndClients();
});

app.get('/auth/logout/all', authToken, function(req, res) {
  const username = req.jwt.sub;
  const userClients = [];
  const userRefreshTokens = Object.keys(refreshTokens).filter(k => {
    if (refreshTokens[k].sub === username) {
      userClients.push(refreshTokens[k].clientId);
      return true;
    }
    return false;
  });
  userRefreshTokens.forEach(token => {
    console.log('deleting refresh token', token);
    delete refreshTokens[token];
  });
  userClients.forEach(client => {
    console.log('deleting client', client);
    delete clients[client];
  });
  res.end();
  showRefreshTokensAndClients();
});

app.post('/auth/refresh', function(req, res) {
  const refreshToken = req.body.refreshToken;
  if (refreshToken && refreshTokens[refreshToken]) {
    if (refreshTokens[refreshToken].exp > Date.now()) {
      const token = jwt.sign({
        sub: refreshTokens[refreshToken].sub,
        exp: parseInt((Date.now() + TOKEN_EXPIRATION) / 1000),
        iss: 'token-based-jwt-demo-server',
      }, SECRET);
      res.json({
        jwt: token,
      });
    } else {
      delete clients[refreshTokens[refreshToken].clientId];
      delete refreshTokens[refreshToken];
      res.status(403).end();
    }
    showRefreshTokensAndClients();
  } else {
    res.status(401).end();
  }
});

app.get('/profile', [authToken, authClientId], function(req, res) {
  res.json(subjects[req.jwt.sub]);
});

app.listen(PORT);
console.log('Server started at port #', PORT);