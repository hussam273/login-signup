const express = require('express');
const bcrypt = require("bcryptjs");
const mongodb = require("mongodb");
const ObjectId = mongodb.ObjectId;

const db = require('../data/database');

const router = express.Router();

router.get('/', function (req, res) {
  res.render('welcome');
});

router.get('/signup', function (req, res) {
  let inputData = req.session.inputData;
  if(!inputData){
    inputData = {
      erorrMessage : "",
      email : "",
      confirmEmail : "",
      password : ""
    };
  }
  req.session.inputData = null;
  res.render('signup', {inputData : inputData});
});

router.get('/login', function (req, res) {
  let inputData = req.session.inputData;
  if(!inputData){
    inputData = {
      erorrMessage : "",
      email : "",
      password : ""
    };
  }
  req.session.inputData = null;
  res.render('login', {inputData : inputData});
});

router.post('/signup', async function (req, res) {
  const userData = {
    email : req.body.email,
    confirmEmail : req.body["confirm-email"],
    password : await bcrypt.hash(req.body.password,12) 
  };

  if(userData.email !== userData.confirmEmail){
    req.session.inputData = {
      erorrMessage : "the both email are not same",
      email : userData.email,
      confirmEmail : userData.confirmEmail,
      password : req.body.password
    };
    req.session.save(function(){
      res.redirect("/signup");
    })
    console.log("the both email are not same");
    return;
  }

  const existingEmail = await db.getDb().collection("users").findOne({email : userData.email});
  if(existingEmail){
    req.session.inputData = {
      erorrMessage : "we already have this email",
      email : userData.email,
      confirmEmail : userData.confirmEmail,
      password : req.body.password
      };
    req.session.save(function(){
      res.redirect("/signup");
    })
    console.log("we already have this email");
    return
  }

  await db.getDb().collection("users").insertOne({email : userData.email, password: userData.password});

  res.redirect("/login");
});

router.post('/login', async function (req, res) {
  const enterdUserData = {
    email : req.body.email,
    password : req.body.password
  };

  const existingEmail = await db.getDb().collection("users").findOne({email : enterdUserData.email});

  if(!existingEmail) {
    req.session.inputData = {
      erorrMessage : "there is no email like this one",
      email : enterdUserData.email,
      password : req.body.password
      };
    req.session.save(function(){
      res.redirect("/login");
    })
    console.log("there is no email like this one");
    return
  }
  const equalPassword = await bcrypt.compare(enterdUserData.password, existingEmail.password);
  if(!equalPassword) {
    req.session.inputData = {
      erorrMessage : "password is wrong",
      email : enterdUserData.email,
      password : req.body.password
      };
    req.session.save(function(){
      res.redirect("/login");
    })
    console.log("password is wrong");
    return;
  }

  req.session.user = {id : existingEmail._id.toString(), email: existingEmail.email};
  req.session.isAuthenticated = true;
  req.session.save(function(){
    res.redirect("/profile");
  });
});

router.get('/admin', async function (req, res) {
  if (!res.locals.isAuthenticated) {
    return res.status(401).render("401");
  }
  if (!res.locals.isAdmin){
    return res.status(403).render("403");
  }
  res.render('admin');
});

router.get('/profile', function (req, res) {
  if (!res.locals.isAuthenticated) {
    return res.status(401).render("401");
  }
  res.render('profile');
});

router.post('/logout', function (req, res) {
  req.session.user = null;
  req.session.isAuthenticated = false;
  res.redirect("/");
});

module.exports = router;