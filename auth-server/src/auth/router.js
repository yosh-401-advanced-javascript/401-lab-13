'use strict';

const express = require('express');
const authRouter = express.Router();

const User = require('./users-model.js');
const auth = require('./middleware.js');
const oauth = require('./oauth/google.js');

/**
 * Authentication router to post
 * @param /POST
 * @param {object} req
 * @param {object} res
 * @param {function} next
 *
 */
authRouter.post('/signup', (req, res, next) => {
  let user = new User(req.body);
  user.save()
    .then( (user) => {
      req.token = user.generateToken();
      req.user = user;
      res.set('token', req.token);
      res.cookie('auth', req.token);
      res.send(req.token);
    }).catch(next);
});

/**
 * * Authentication router to post
 * @param /POST
 * @param {object} req
 * @param {object} res
 * @param {function} next
 */
authRouter.post('/signin', auth, (req, res, next) => {
  res.cookie('auth', req.token);
  res.send(req.token);
});

/**
 * * Authentication router to post
 * @param /GET
 * @param {object} req
 * @param {object} res
 * @param {function} next
 */
authRouter.get('/oauth', (req,res,next) => {
  oauth.authorize(req)
    .then( token => {
      res.status(200).send(token);
    })
    .catch(next);
});

module.exports = authRouter;
