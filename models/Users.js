var mongoose = require('mongoose');
var crypto = require('crypto');
var jwt = require('jsonwebtoken');

var UserSchema = new mongoose.Schema({
	username: {type: String, lowercase: true, unique: true},
	email: {type: String, unique: true},
	hash: String,
	salt: String
});


// Method set Password
UserSchema.methods.setPassword = function(password) {
	//Generating salt for the password
	this.salt = crypto.randomBytes(16).toString('hex');
	
	//Generating hash
	this.hash = crypto.pbkdf2Sync(password, this.salt, 1000, 64).toString('hex');
};


// Method to check whether the password is correct or not
UserSchema.methods.validPassword = function(password) {
	var hash = crypto.pbkdf2Sync(password, this.salt, 1000, 64).toString('hex');
	
	return this.hash === hash;
}

//method to generate the json web token for authentication purposes
UserSchema.methods.generateJWT = function() {
	
	//Set expiration day of the password to 90 days
	var today = new Date();
	var exp = new Date(today);
	exp.setDate(today.getDate() + 60);
	
	//returning the json signed with secret
	return jwt.sign({
		_id: this._id,
		username: this.username,
		exp: parseInt(exp.getTime()/1000),	
	}, 'SECRET');	//Move this 'secret' out of the codebase
};



mongoose.model('User', UserSchema);