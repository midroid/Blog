var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var mongoose = require('mongoose');
var user = mongoose.model('User');

passport.use(new LocalStrategy(
	function(username, password, done) {
		User.findOne({username: username }, function (err, user) {
			if (err) { return done(err); }
			if (!user) {
				return done(null, false, { message: 'Incorrect username.' }); // Later change it to incorrect username or password
			} 
			if (!user.validPassword(password)) {
				return done(null, false, { message: 'Incorrect password.'}); // Later change it to incorrect username or password
			}
			return done(null, user);
		});
	}
));