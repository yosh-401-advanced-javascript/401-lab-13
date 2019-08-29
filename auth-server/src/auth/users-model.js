'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const tokens = {};
const users = new mongoose.Schema({
  username: {type:String, required:true, unique:true},
  password: {type:String, required:true},
  email: {type: String},
  role: {type: String, default:'user', enum: ['admin','editor','user']},
});

users.pre('save', function(next) {
  bcrypt.hash(this.password, 10)
  .then(hashedPassword => {
    this.password = hashedPassword;
    next();
  })
  .catch(console.error);
});

users.statics.createFromOauth = function(email) {

  if(! email) { return Promise.reject('Validation Error'); }

  return this.findOne( {email} )
  .then(user => {
    if( !user ) { throw new Error('User Not Found'); }
    console.log('Welcome Back', user.username);
    return user;
  })
  .catch( error => {
    console.log('Creating new user');
    let username = email;
    let password = 'none';
    return this.create({username, password, email});
  });

};

users.statics.authenticateToken = function(token) {
  const decryptedToken = jwt.verify(token, process.env.SECRET || 'secret');
  const query = {_id: decryptedToken.id};
  const oneUseToken = tokens.hasOwnProperty(token);


  if(oneUseToken === true) {
    console.log('invalid token');
    return Promise.reject('invalid token stuff')
    .then(process.env.EXPIRES === false);
  }else if( oneUseToken === false ) {
    tokens[token ] = token;
    return this.findOne(query)
        .then(process.env.EXPIRES === true);
  }
};

users.statics.authenticateBasic = function(auth) {
  let query = {username:auth.username};
  return this.findOne(query)
  .then( user => user && user.comparePassword(auth.password) )
  .catch(error => {throw error;});
};

users.methods.comparePassword = function(password) {
  return bcrypt.compare( password, this.password )
  .then( valid => valid ? this : null);
};

users.methods.generateToken = function() {

  let token = {
    id: this._id,
    role: this.role,
  };

  if (process.env.SINGLEUSE === true) {
    return jwt.sign(token, process.env.SECRET || 'secret');
  } else {
    return jwt.sign(token, process.env.SECRET || 'secret', {expiresIn: 30});
  }
}

  module.exports = mongoose.model('users', users);
