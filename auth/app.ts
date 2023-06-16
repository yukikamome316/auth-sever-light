import express from 'express'
import bodyParser from 'body-parser'
import jwt from 'jsonwebtoken'
import { match } from 'path-to-regexp'
import { NotificationPathMatcher } from './types'
import sqlite3 from 'sqlite3';
import NodeCache from 'node-cache';
import crypto from 'crypto';
import fs from 'fs';

const NOTIFICATION_JWT_SECRET = fs.readFileSync('../res/cert/private.key') || 'superdupersecretkey'
const USER_CONFIG_PATH = "/:username";
const GET_DATA_PATH = "/get-data";

const nodeCache = new NodeCache();

const issueNotificationToken = (url: string[]) => {
  return jwt.sign(
    {
      path: url
    },
    NOTIFICATION_JWT_SECRET,
    { algorithm: 'RS256',
      expiresIn: '12h'
    },
  );
}

const PathAllowedForUser = (user: User, path: string[]) => {
  // roleがAdmin場合は、全てのURLを許可
  if (user.role === 'Admin') {
    return true;
  }

  let isValid = true;
  for (let val of path) {
    if (val === GET_DATA_PATH) continue;
    const matchedPath = match<NotificationPathMatcher>(USER_CONFIG_PATH)(val);
    if (matchedPath) {
      isValid = matchedPath.params.username === user.name;
    }
  };

  return isValid;
}

interface User {
  id: number,
  name: string,
  password: string,
  role: string
}

const login = async (username: string, password: string) => {
  const db = new sqlite3.Database('./db/users.test.db');
  // パスワードチェック
  const user = await new Promise<User>((resolve) => {
    db.get("SELECT * FROM users WHERE name = ?", username, (err, row: User) => {
      resolve(row);
    });
  });
  
  if (!user) return false;
  const savedPassword = user.password;

  if (!savedPassword || savedPassword !== password) {
    return false
  }

  return user;
}

// const signup = (username: string, password: string) => {
//   // 登録済みのユーザがいれば失敗
//   if (passwordTable.has(username)) {
//     return false
//   }

//   passwordTable.set(username, password)
//   return true
// }

const app = express()

app.use(bodyParser.json());

// CORS許可
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*')
  res.header('Access-Control-Allow-Headers', 'Content-Type')
  next()
})

interface Cookies {
  sessionId:string
}

const cookieParser: (str:string | undefined) => Cookies = (str)=> {
  if(!str) return {sessionId:''};
  const cookies = {sessionId:''};
  str.split(';').forEach((cookie)=>{
      let parts = cookie.split('=');
      let key = parts[0];
      let value = parts[1];
      let part = {[key]: value}
      Object.assign(cookies, part);
  });
  return cookies;
}

const createSessionId = (user: User) => {
  const sha256 = crypto.createHash('sha256');
  sha256.update(new Date().toISOString() + user.name);
  return sha256.digest().toString('hex');
}

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = await login(username, password);
  if (user) {
    const sid = createSessionId(user);
    nodeCache.set(sid, user, 3 * 60 * 60);
    
    res.cookie('sessionId', sid, {
      httpOnly: false
    })
    // res.send({ success: true })
    res.send({ success: true, sessionId: sid});
  } else {
    res.send({ success: false })
  }
})

// app.post('/signup', (req, res) => {
//   const { username, password } = req.body

//   const result = signup(username, password)
//   res.send({ success: result })
// })

app.post('/generate-token', async (req, res) => {
  const { path } = req.body
  if (!path) {
    res.send({ success: false });
    return;
  }

  const cookies = cookieParser(req.headers.cookie);
  const sessionId = cookies.sessionId;
  const user: User | undefined = nodeCache.get(sessionId);

  if (user && PathAllowedForUser(user, path)) {
    const notificationToken = issueNotificationToken(path)
    res.send({
      success: true,
      token: notificationToken
    })
  } else {
    res.send({ success: false })
  }
})

app.listen(process.env.PORT || 3000)
