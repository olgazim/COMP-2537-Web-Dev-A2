require("./utils.js");
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const fs = require('fs');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const mongoose = require('mongoose');
const { ObjectId } = require('mongodb');
const MongoStore = require('connect-mongo');

mongoose.connect

const app = express();
const port = process.env.PORT || 3000;
const expirationPeriod = 1000 * 60 * 60;
const Joi = require("joi");
const { emit } = require("process");
var users = []; 

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');
const userCollection = database.db(mongodb_database).collection('users');
var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.set('view engine', 'ejs');
app.use(express.static("public"));
app.use(express.urlencoded({ extended: false })); // built-in middleware func
app.use(session({
    secret: node_session_secret,
    store: mongoStore, 
    saveUninitialized: false,
    resave: true
}));

function isValidSession(req) {
    return req.session.authenticated;
}

function validateSession(req, res, next) {
    if (isValidSession) {
        next();
    } else {
        req.redirect("home");
    }
}

function isAdmin(req) {
    return req.session.is_admin;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        var target = "/";
        res.status(403);
        res.render("error-page", {errorMsg: "Not Authorized.", target: target});
        return;
    }
    else {
        next();
    }
}


app.get('/', (req, res) => {
    if (req.session.authenticated) {
        const username = req.session.username;
        res.render("home-logged-in", {userName: username});
    } else {

        res.render("home");
    }
});


app.get("/nosql-injection", async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

    const schema = Joi.string().max(20).required();

	const validationResult = schema.validate(req.body);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({ username: username }).project({ username: 1, email: 1, password: 1, _id: 1 }).toArray();
    res.send();
});

app.get('/signupFailure', (req, res) => {
    var missingParam = req.query.missing;
    console.log(missingParam);
    var errorMsg = "Please, try again"
    var target = "/signup";
    if (missingParam == 1) {
        errorMsg =  "All fields are missing. Please, try again"; 
    } else if (missingParam == 2) {
        errorMsg =  "Username and email are missing. Please, try again";
    } else if (missingParam == 3) {
        errorMsg =  "Username and password are missing. Please, try again";
    } else if (missingParam == 4) {
        console.log("4")
        errorMsg = "Email and password are missing. Please, try again";
    } else if (missingParam == 5) {
        errorMsg =  "Username is missing. Please, try again";
    } else if (missingParam == 6) {
        errorMsg =  "Email is missing. Please, try again";
    } else if (missingParam == 7) {
        errorMsg =  "Password is missing. Please, try again";
    } 
    res.render("error-page", { errorMsg: errorMsg, target: target });
});


app.get("/signup",  (req, res) => { 
    res.render("signup");
});

app.post('/signup', async (req, res) => { 

    var username = req.body.user_name;
    var email = req.body.email;
    var password = req.body.password;
    console.log("inside signup");

    if (!username && !email && !password) {
        console.log("All fields are missing.");
        res.redirect('/signupFailure?missing=1');
        return;
    } else if (!username && !email) {
        console.log("Username and email are missing.");
        res.redirect('/signupFailure?missing=2');
        return;
    } else if (!username && !password) {
        console.log("Username and password are missing.");
        res.redirect('/signupFailure?missing=3');
        return;
    } else if (!email && !password) {
        console.log("Email and password are missing.");
        res.redirect('/signupFailure?missing=4');
        return;
    } else if (!username) {
        console.log("Name is missing.");
        res.redirect('/signupFailure?missing=5');
        return;
    } else if (!email) {
        console.log("Email is missing.");
        res.redirect('/signupFailure?missing=6');
        return;
    } else if (!password) {
        console.log("Password is missing.");
        res.redirect('/signupFailure?missing=7');
        return;
    } 

    const schema = Joi.object({
        username: Joi.string().alphanum().max(30).required(),
        email: Joi.string().max(30).required(),
        password: Joi.string().max(20).required(),
    });

    const validationResult = schema.validate({ username, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect('/signup');
        return;
    }

    var hashedPassword = await bcrypt.hashSync(password, saltRounds);
    console.log(hashedPassword);

    await userCollection.insertOne({
        username: username,
        email: email,
        password: hashedPassword,
        is_admin: false
    });
    console.log("user inserted");

    req.session.authenticated = true;
    req.session.username = username;
    req.session.is_admin = false;
    res.redirect('/members');
});


app.get('/loginFailure', (req, res) => {
    var errorMsg = "Invalid email or password.  Please, try again";
    var target = "/login";
    res.render("error-page", { errorMsg: errorMsg, target: target });
});

app.get("/login", (req, res) => { 
    res.render("login");
});

app.post('/login', async (req, res) => { 
    console.log("inside login")
    var email = req.body.email;
    var password = req.body.password;
    
    const schema = Joi.object({
        email: Joi.string().max(30).required(),
        password: Joi.string().max(20).required(),
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const user = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, is_admin: 1}).toArray();

    if (!user) {
        console.log("User not found");
        res.redirect("/loginFailure");
        return;
    }
    const passwordMatch = await bcrypt.compare(password, user[0].password);

    if (passwordMatch) {
        req.session.authenticated = true;
        req.session.username = user[0].username;
        req.session.email = email;
        req.session.is_admin = user[0].is_admin;
        req.session.cookie.maxAge = expirationPeriod;
        res.redirect('/members');
        return;
    } else {
        console.log("Invalid email or password");
        res.redirect("/loginFailure");
        return;
    }
});

app.use("/loggedIn", validateSession);
app.get("/loggedIn", (res, req) => {
    console.log("loggedin");
    console.log(req.session.is_admin);
    res.redirect("/members");
})

app.get("/members", (req, res) => { 
    if (!req.session.authenticated) {
        res.redirect('/');
        console.log("no session");
    } else {
    console.log("inside members");

    // retrieve the username from the session variable
        const username = req.session.username;
        res.render("members", { userName: username});
    }
});

app.use("/admin", validateSession, adminAuthorization);
app.get("/admin", async (req, res) => {
    const result = await userCollection.find({}).project({ username: 1, email: 1, is_admin: 1, _id:1}).toArray();
    currentUserEmail = req.session.email;
    res.render("admin-dashboard", { users: result, currentUserEmail: currentUserEmail});
});

app.post("/admin/updateRole/:userId", async (req, res) => {
    const userId = req.params.userId;
    const user = await userCollection.findOne({ _id:  new ObjectId(userId) });
    const is_admin = user.is_admin;
    const is_admin_new = !is_admin;
    await userCollection.updateOne(
        { _id: new ObjectId(userId) },
        { $set: { is_admin: is_admin_new } });
    res.redirect("/admin");
});

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

app.get("*", (req, res) => { 
    res.status(404).render("page-not-found");
});

app.listen(port, () => {
    console.log(`Application is listening at http://localhost:${port}`);
});
