CREATE DATABASE users CHARACTER SET UTF8;

CONNECT users;

CREATE TABLE IF NOT EXISTS users (
  id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
  name character varying(255) NOT NULL,
  password character varying(255) NOT NULL,
  role TEXT NOT NULL
);
