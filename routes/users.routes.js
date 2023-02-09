var express = require('express');
var router = express.Router();

const mongoose = require('mongoose')

const bcryptjs = require('bcryptjs');
const saltRounds = 10;

const User = require('../models/User.model')

const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard.js');

/* GET users listing. */
router.get('/signup', isLoggedOut, (req, res, next) => {
  res.render('auth/signup.hbs');
});

router.post('/signup', isLoggedOut, (req, res, next) => {
  console.log('The form data: ', req.body);

  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    res.render('auth/signup.hbs', { errorMessage: 'All fields are mandatory. Please provide your username, email and password.' });
    return;
  }

  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
  if (!regex.test(password)) {
    res
      .status(500)
      .render('auth/signup', { errorMessage: 'Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.' });
    return;
  }
 
  bcryptjs
    .genSalt(saltRounds)
    .then((salt) => {
      return bcryptjs.hash(password, salt)
    })
    .then((hashedPassword) => {
      return User.create({
        // username: username
        username,
        email,
        // passwordHash => this is the key from the User model
        //     ^
        //     |            |--> this is placeholder (how we named returning value from the previous method (.hash()))
        passwordHash: hashedPassword
      });
    })
    .then((userFromDB) => {
      console.log('Newly created user is: ', userFromDB);
      res.redirect('/users/login')
    })
    .catch(error => {
      if (error instanceof mongoose.Error.ValidationError) {
        res.status(500).render('auth/signup', { errorMessage: error.message });
      } else if (error.code === 11000) {
        res.status(500).render('auth/signup', {
           errorMessage: 'Username and email need to be unique. Either username or email is already used.'
        });
      } else {
        next(error);
      }
    })


})

router.get('/login', isLoggedOut, (req, res, next) => {
  res.render('auth/login.hbs')
})

router.post('/login', isLoggedOut, (req, res, next) => {
  const { email, password } = req.body;
 
  if (!email || !password) {
    res.render('auth/login.hbs', {
      errorMessage: 'Please enter both, email and password to login.'
    });
    return;
  }
 
  User.findOne({ email })
    .then(user => {
      if (!user) {
        res.render('auth/login', { errorMessage: 'Email is not registered. Try with other email.' });
        return;
      } else if (bcryptjs.compareSync(password, user.passwordHash)) {
        req.session.user = user
        console.log('SESSION =====> ', req.session);
        res.redirect('/users/profile');
      } else {
        res.render('auth/login', { errorMessage: 'Incorrect password.' });
      }
    })
    .catch(error => next(error));
});

router.get('/profile', isLoggedIn, (req, res, next) => {
  const user = req.session.user
  console.log('SESSION =====> ', req.session);
  res.render('users/user-profile.hbs', { user })
})

router.get('/logout', isLoggedIn, (req, res, next) => {
  req.session.destroy(err => {
    if (err) next(err);
    res.redirect('/');
  });
});

module.exports = router;