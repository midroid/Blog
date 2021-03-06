var express = require('express');
var router = express.Router();
var passport = require('passport');
var mongoose = require('mongoose');
var User = mongoose.model('User');
var jwt = require('express-jwt');
var auth = jwt({secret: 'SECRET', userProperty: 'payload'});

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index');
});

/* User registration logic */
router.post('/register', function(req, res, next){
  
  if(!req.body.username || !req.body.password){
    return res.status(400).json({message: 'Please fill out  all fields'});
  }
  
  var user = new User();
  
  user.username = req.body.username;
  
  user.setPassword(req.body.password);
  
  user.save(function (err){
    if(err){ return next(err); }
    
    return res.json({token: user.generateJWT})
  });
});


/* User Login login */
router.post('/login', function(req, res, next){
  if(!req.body.username || !req.body.password){
    return res.status(400).json({message: 'Please fill out all fields'});
  }
  
  passport.authenticate('local', function(err, user, info){
    if(err) { return next(err); }
    
    if(user) {
      return res.json({token: user.generateJWT()});
    } else {
      return res.status(401).json(info);
    }
  })(req, res, next);
});


module.exports = router;
