if(process.env.NODE_ENV !== "production"){
    require("dotenv").config()
}

const express = require("express")
const app = express()
const bcrypt = require("bcrypt")
const passport = require("passport")
const flash = require("express-flash")
const session = require("express-session")
const methodOverride = require("method-override")

//configuring passport for login credentials
const initializePassport = require("./passport-config")
initializePassport(
    passport,
    email => {
        return users.find(user => user.email === email)
    },
    id => {
        return users.find(user => user.id === id);
    }
)

//temporary storage
const users = [];

app.set("view-engine", "ejs")
app.use(express.urlencoded({extended: false}))
app.use(flash())
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(methodOverride("_method"))
app.use(express.static("public"))

//home route
app.get("/", checkAuthenticated, (req, res) => {
    res.render("index.ejs", {name: req.user.name})
})
//login route
app.get("/login", checkNotAuthenticated, (req, res) => {
    res.render("login.ejs")
})

//handles redirection of client to home page and restrains from login access once logged in
app.post("/login", checkNotAuthenticated, passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true
}))

//register route
app.get("/register", checkNotAuthenticated, (req, res) => {
    res.render("register.ejs")
})

app.post("/register", checkNotAuthenticated, async(req,res) => {
    try {
        //hashing password created by user
        const hashedPassword = await bcrypt.hash(req.body.password, 10)
        users.push({
            id: Date.now().toString(),
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword
        })
        res.redirect("/login")
    } catch {
        res.redirect("/register")
    }
    console.log(users)
})
//logout route using methodOverride
app.delete("/logout", (req, res, next) => {
    req.logOut(function(error){
        if(error){
            return next(error);
        }
        res.redirect("/login");
    });
})

//checks if user is logged in and allows to access the home route
function checkAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return next();
    }
    res.redirect("/login");
}

//checks if user is logged in and denies access to the login/register routes
function checkNotAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return res.redirect("/");
    }
    return next();
}

app.listen(3000)