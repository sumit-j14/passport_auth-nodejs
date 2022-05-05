//required packages 
const passport = require('passport')
const bcrypt = require('bcrypt')
const flash = require('express-flash')
require('dotenv').config()
const express = require('express')
const app = express()
const session = require('express-session')
const methodOverride = require('method-override')


// passport schema
const makePassport = require('./passport-config')
makePassport(
  passport,
  email => users.find(user => user.email === email),
  id => users.find(user => user.id === id)
)

//array which is a local variable storage here 
// in roduction level these users will be stored in a database
const users = []

//declaration of middlewares
app.set('view-engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(flash())
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(methodOverride('_method'))

 

// application routes
app.get('/', is_authenticated, (req, res) => {
  // console.log("listening at port number 3000");
  res.render('index.ejs', { name: req.user.name })
})

app.get('/login', not_authenticated, (req, res) => {
  console.log("/login get request");
  res.render('login.ejs')
})

app.post('/login', not_authenticated, passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true
}))

app.get('/register', not_authenticated, (req, res) => {
  console.log("/registerget request")
  res.render('register.ejs')
})

app.post('/register', not_authenticated, async (req, res) => {
  try {
    const encrypted_password = await bcrypt.hash(req.body.password, 10)
    users.push({

      // there is an id attribute which is the time at user creation
      id: Date.now().toString(),
      name: req.body.name,
      email: req.body.email,
      password: encrypted_password
    })
    res.redirect('/login')
  } catch {
    res.redirect('/register')
  }
})

app.delete('/logout', (req, res) => {
  req.logOut()
  res.redirect('/login')
})

function is_authenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next()
  }

  res.redirect('/login')
}

function not_authenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect('/')
  }
  next()
}

//spin up server
app.listen(3000)