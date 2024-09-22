const path = require('path');

const express = require('express');

const db = require('./data/database');
const demoRoutes = require('./routes/demo');

const session = require("express-session");
const mongodbStore = require("connect-mongodb-session");

const MongoDBStore = mongodbStore(session);
const sessionStore = new MongoDBStore({
  uri : 'mongodb://localhost:27017',
  databaseName : "auth-demo",
  collection : "sessions"
});

const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static('public'));
app.use(express.urlencoded({ extended: false }));

app.use(session({
  secret : "super-secret",
  resave : false,
  saveUninitialized : false,
  store : sessionStore
}));

app.use(async function(req,res,next){
  const isAuthenticated = req.session.isAuthenticated;
  if(!isAuthenticated){
    return next();
  }
  const user = await db.getDb().collection("users").findOne({email : req.session.user.email});
  const isAdmin = user.isAdmin;
  res.locals.isAuthenticated = isAuthenticated;
  res.locals.isAdmin = isAdmin;
  next();
})

app.use(demoRoutes);

// app.use(function(error, req, res, next) {
//   res.render('500');
// })

db.connectToDatabase().then(function () {
  app.listen(3000);
});