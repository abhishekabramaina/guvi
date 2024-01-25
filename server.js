// app.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const flash = require('express-flash');
const bodyParser = require('body-parser');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const ejs = require('ejs');


const app = express();
const port = 3000;

const pool = new Pool({
    connectionString: process.env.ELEPHANTSQL_URL, // Use the connection URL provided by ElephantSQL
    ssl: {
      rejectUnauthorized: false, // Disable SSL certificate verification for ElephantSQL
    },
  });




app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'your_secret_key', resave: true, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

app.set('view engine', 'ejs');


// Define user serialization and deserialization
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  pool.query('SELECT * FROM users WHERE id = $1', [id], (err, result) => {
    const user = result.rows[0];
    done(err, user);
  });
});

// Configure local strategy for login
passport.use(
  new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
    pool.query('SELECT * FROM users WHERE email = $1', [email], (err, result) => {
      const user = result.rows[0];

      if (!user) {
        return done(null, false, { message: 'Incorrect email.' });
      }

      bcrypt.compare(password, user.password, (err, res) => {
        if (res) {
          return done(null, user);
        } else {
          return done(null, false, { message: 'Incorrect password.' });
        }
      });
    });
  })
);

// Routes
app.get('/', (req, res) => {
  res.render('index');
});

app.get('/login', (req, res) => {
    res.render('login', { message: req.flash('error') });
  });
  
app.post('/login', passport.authenticate('local', {
    successRedirect: '/profile',
    failureRedirect: '/login',
    failureFlash: true
  }));


app.get('/register', (req, res) => {
    res.render('register', { message: req.flash('error') });
  });
  
 
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  pool.query('INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *', [email, hashedPassword], (err, result) => {
    const user = result.rows[0];
    req.login(user, (err) => {
      if (err) throw err;
      res.redirect('/profile');
    });
  });
});

app.get('/profile', isAuthenticated, (req, res) => {
    res.render('profile', { user: req.user });
  });
  

  app.get('/edit-profile', isAuthenticated, (req, res) => {
    res.render('edit-profile', { user: req.user });
  });

  app.post('/edit-profile', isAuthenticated, (req, res) => {
    const { age, dob, contact, city, organization } = req.body;
  
    // Update user details in the database
    pool.query(
      'UPDATE users SET age = $1, dob = $2, contact = $3, city = $4, organization = $5 WHERE id = $6 RETURNING *',
      [age, dob, contact, city, organization, req.user.id],
      (err, result) => {
        if (err) throw err;
  
        const updatedUser = result.rows[0];
        req.login(updatedUser, (err) => {
          if (err) throw err;
          res.redirect('/profile');
        });
      }
    );
  });

app.get('/logout', (req, res) => {
  req.logout(function(err) {
    if (err) {
      return next(err);
    }
    res.redirect('/');
  });
});


function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  res.redirect('/login');
}

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

