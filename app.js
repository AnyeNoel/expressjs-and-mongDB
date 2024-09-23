require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passportLocalMongoose = require("passport-local-mongoose");
const passport = require("passport");
const findOrCreate = require('mongoose-findorcreate')
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));
app.use(session({
  secret: "I am a great man in the making.",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb://0.0.0.0:27017/secretDB", {useNewUrlParser: true});

const userSchema = mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate);
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileUrl:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req, res){
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] }));

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect secrete.
      res.redirect("/secrets");
    });

app.get("/login", function(req, res){
  res.render("login");
});
app.get("/register", function(req, res){
  res.render("register");
});


app.get("/secrets", function(req, res){
 User.find({secret: {$ne: null}}).then(function(foundUsers){
   res.render("secrets", {usersWithSecret: foundUsers});
 });

});

app.get("/submit",function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }

});

app.post("/submit", function(req, res){
  const asecret = req.body.secret;

  // console.log(req.user);

  User.findById(req.user._id).then(function(founduser){
    founduser.secret = asecret;
    founduser.save().then(function(){
      res.redirect("/secrets");
    });
  });

});

app.get("/logout", function(req, res, next){
req.logout(function(err){
  if (err){
    console.log(err)
  } else {
    res.redirect("/");
  }
});


});

app.post("/register", function(req, res){

  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err){
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  })

});
app.post("/login", function(req, res){
const user = new User({
  email: req.body.username,
  password: req.body.password
});

 req.login(user, function(err){
   if (err){
     console.log(err);
   } else {
     passport.authenticate("local")(req, res, function(){
       res.redirect("/secrets");
     });
   }
 });
});



app.listen(3000, function(){
  console.log("Server started on port 3000");
});
