require("./utils.js");
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const app = express();
const port = process.env.PORT || 3000;
const Joi = require("joi");

const expireTime = 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
    store: mongoStore, 
    saveUninitialized: false, 
    resave: true
}));

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("403");
        return;
    }
    else {
        next();
    }
}
app.get('/', (req, res) => {
    res.render('index', {
        authenticated: req.session.authenticated,
        name: req.session.name
    })
});

app.get('/signup', (req, res) => {
    res.render('signup');
});

app.post('/signupSubmit', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
        name: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email().max(30).required(),
        password: Joi.string().max(20).required()
    });
    const validationResult = schema.validate({name, email, password});

    if (validationResult.error != null) {
        if(name && email && password) {
            var invalidFormat = true;
        }
        res.render("signupSubmit", {
            name,
            email,
            password,
            invalidFormat            
        });
        return;
    }
    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({name: name, email: email, password: hashedPassword});

    req.session.authenticated = true;
	req.session.name = name;
	req.session.cookie.maxAge = expireTime;

    res.redirect("/members");
});

app.get('/login', (req, res) => {
    res.render('login')
});

app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
		{
			email: Joi.string().email().max(30).required(),
            password: Joi.string().max(20).required()
		});
    const validationResult = schema.validate({email, password});
    if (validationResult.error != null) {
        var invalidFormat = true;
        var notFound = false;
        res.render("loginSubmit", {invalidFormat, notFound});
        return;
    }

    const result = await userCollection.find({email: email}).project({email: 1, name: 1, password: 1, user_type: 1, _id: 1}).toArray();

    if (result.length == 1 && await bcrypt.compare(password, result[0].password)) {
        const name = result[0].name;
		req.session.authenticated = true;
		req.session.name = name;
        req.session.email = email;
        req.session.user_type = result[0].user_type;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
		return;
	} else {
        var invalidFormat = false;
        var notFound = true;
        res.render("loginSubmit", {invalidFormat, notFound});
		return;
	}
});

app.get('/members', sessionValidation, (req, res) => {
    var images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg'];
    res.render("members", {user: req.session.name, images: images});
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({name: 1, email: 1, user_type: 1, _id: 1}).toArray();
 
    res.render("admin", {users: result});
});

app.post('/promote/:email', async (req, res) => {
    const email = req.params.email;
    await userCollection.updateOne(
        {email: email},
        {$set: {user_type: 'admin'}}
    );
    res.redirect('/admin');
});

app.post('/demote/:email', async (req, res) => {
    const email = req.params.email;
    await userCollection.updateOne(
        {email: email},
        {$set: {user_type: 'user'}}
    );
    res.redirect('/admin');
});

app.use(express.static(__dirname + "/public"));

app.get(/.*/, (req,res) => {
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+ port);
}); 