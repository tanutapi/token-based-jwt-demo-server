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
  'user01': {
    name: 'Suratose',
    surname: 'Ake',
    address: 'Mahidol University',
    email: 'ake.suratose@address.com',
  },
  'user02': {
    name: 'Nartdanai',
    surname: 'B.',
    address: 'Bangkok, Thailand',
    email: 'ball.nartdanai@address.com',
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
      console.log('  Access token was verified!');
      next();
    } catch (err) {
      console.log('  Error in verifying the access token!', err.message);
      res.status(403).end('Invalid token!');
    }
  } else {
    console.log('  No access token was provided!');
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
  console.log('');
  console.log('============================================');
  console.log('Current Refresh Tokens Table & Clients Table');
  console.log('============================================');
  console.log('Refresh tokens', refreshTokens);
  console.log('Clients', clients);
  console.log('');
}

app.post('/auth/login', function(req, res) {
  const username = req.body.username;
  const password = req.body.password;
  const clientId = req.body.clientId;
  console.log('POST: /auth/login');
  console.log('  Logging in with username:', username, 'password:', password, 'clientId', clientId);
  if (
    username && password && 
    clientId &&
    ((username === 'admin' && password === 'password') ||
    (username === 'user01' && password === 'password01') ||
    (username === 'user02' && password === 'password02'))
  ) {
    console.log('  Credential match!');
    const token = jwt.sign({
      sub: username,
      exp: parseInt((Date.now() + TOKEN_EXPIRATION) / 1000),
      iss: 'token-based-jwt-demo-server',
    }, SECRET);
    const refreshToken = uuidv4();

    if (clients[clientId]) {
      delete refreshTokens[clients[clientId]];
    }

    refreshTokens[refreshToken] = {
      sub: username,
      exp: Date.now() + REFRESH_TOKEN_EXPIRATION,
      clientId: clientId,
    };

    clients[clientId] = refreshToken;

    const result = {
      jwt: token,
      refresh: refreshToken,
    };

    console.log('  Return tokens back to user:', result);

    res.json(result);

    showRefreshTokensAndClients();
  } else {
    console.log('  Credential does not match!');
    res.status(400).json({err: 'Invalid username or password'});
  }
});

app.get('/auth/logout', [authToken, authClientId], function(req, res) {
  console.log('GET: /auth/logout');
  const refreshToken = clients[req.clientId];
  delete refreshTokens[refreshToken];
  delete clients[req.clientId];
  console.log(`  Done deleting refresh token: ${refreshToken} from the memory.`);
  console.log(`  Done deleting client: ${req.clientId} from the memory.`);
  res.end();
  showRefreshTokensAndClients();
});

app.get('/auth/logout/all', authToken, function(req, res) {
  console.log('GET: /auth/logout/all');
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
    console.log('  deleting refresh token', token);
    delete refreshTokens[token];
  });
  userClients.forEach(client => {
    console.log('  deleting client', client);
    delete clients[client];
  });
  console.log(`  Done deleting all refresh tokens of username: ${username} from the memory.`);
  console.log(`  Done deleting all clients of username: ${username} from the memory.`);
  res.end();
  showRefreshTokensAndClients();
});

app.post('/auth/refresh', function(req, res) {
  console.log('POST: /auth/refresh');
  const refreshToken = req.body.refreshToken;
  if (refreshToken && refreshTokens[refreshToken]) {
    if (refreshTokens[refreshToken].exp > Date.now()) {
      const token = jwt.sign({
        sub: refreshTokens[refreshToken].sub,
        exp: parseInt((Date.now() + TOKEN_EXPIRATION) / 1000),
        iss: 'token-based-jwt-demo-server',
      }, SECRET);
      
      const result = {
        jwt: token,
      };

      console.log('  Return new access token back to user:', result);

      res.json(result);
    } else {
      console.log('  Error: refresh token was expired!');
      delete clients[refreshTokens[refreshToken].clientId];
      delete refreshTokens[refreshToken];
      res.status(403).end();
    }
    showRefreshTokensAndClients();
  } else {
    console.log('  Error: no refresh token found in the memory!');
    res.status(401).end();
  }
});

app.get('/profile', [authToken, authClientId], function(req, res) {
  const profile = subjects[req.jwt.sub];
  if (profile) {
    console.log('  Return user\'s profile', profile);
    res.json(profile);
  } else {
    console.log('  No profile found for this user!');
    res.json({});
  }
});

app.listen(PORT);
console.log('Server started at port #', PORT);
