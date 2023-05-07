require("./utils.js");
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const fs = require('fs');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const mongoose = require('mongoose');
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
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/a2_sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})


app.use(express.static("public"));
app.use(express.urlencoded({ extended: false })); // built-in middleware func
app.use(session({
    secret: node_session_secret,
    store: mongoStore, 
    saveUninitialized: false,
    resave: true
}));


app.get('/', (req, res) => {
    res.sendFile(__dirname + "/index.html");
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
    fs.readFile(__dirname + "/pages/error-page.html", "utf8", (err, data) => {
            // Replace the placeholder with the error message
        var modifiedData = data.replace("{errorMsg}", errorMsg);
        modifiedData = modifiedData.replace("{target}", target);

            // Send the modified content to the client
            res.send(modifiedData);
    });
});


app.get("/signup",  (req, res) => { 
    res.sendFile(__dirname + "/pages/signup.html");
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
    });
    console.log("user inserted");

    req.session.authenticated = true;
    req.session.username = username;
    res.redirect('/members');
});


app.get('/loginFailure', (req, res) => {
    var errorMsg = "Invalid email or password.  Please, try again";
    var target = "/login";
    fs.readFile(__dirname + "/pages/error-page.html", "utf8", (err, data) => {
        // Replace the placeholder with the error message
        var modifiedData = data.replace("{errorMsg}", errorMsg);
        modifiedData = modifiedData.replace("{target}", target);
        // Send the modified content to the client
        res.send(modifiedData);
    });

});

app.get("/login", (req, res) => { 
    res.sendFile(__dirname + "/pages/login.html");
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

    const user = await userCollection.findOne({ email: email });

    if (!user) {
        console.log("User not found");
        res.redirect("/loginFailure");
        return;
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
        req.session.authenticated = true;
        req.session.username = user.username;
        req.session.cookie.maxAge = expirationPeriod;
        res.redirect('/members');
        return;
    } else {
        console.log("Invalid email or password");
        res.redirect("/loginFailure");
        return;
    }
});

app.get("/loggedIn", (res, req) => {
    if(!req.session.authenticated) {
        res.redirect('/login');
    }
    res.redirect("/members");
})


app.get("/members", (req, res) => { 
    if (!req.session.authenticated) {
        res.redirect('/');
        console.log("no session");
    } else {
    console.log("inside members");
    const randomNumber = Math.floor(Math.random() * 3) + 1;
    const image = `${randomNumber}.jpg`;
    const imagePath = "/images/" + image;

    // retrieve the username from the session variable
    const username = req.session.username;
    fs.readFile(__dirname + "/pages/members.html", "utf8", (err, data) => {
        // Replace the placeholder with the error message
        var modifiedData = data.replace("{userName}", username);
        modifiedData = modifiedData.replace("{target}", imagePath);

        // Send the modified content to the client
        res.send(modifiedData);
    });}
});


app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

// // only for authenticated users
// const authenticatedUsersOnly = (req, res, next) => {
//   if (!req.session.GLOBAL_AUTHENTICATED) {
//     return res.status(401).json({ error: 'Not authenticated' });
//   }
//   next();
// };
// app.use(authenticatedUsersOnly);

app.get("*", (req, res) => { 
    res.status(404).sendFile(__dirname + "/pages/page-not-found.html");
});


app.listen(port, () => {
    console.log(`Application is listening at http://localhost:${port}`);
});