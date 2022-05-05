const bcrypt = require('bcrypt')

// passport login stragetgy contains the logic of authentication as user wants
const User_Strategy = require('passport-local').Strategy

function begin_authentication(passport, getUserByEmail, getUserById) 
{
  // this asynchronous function returns the valid user if it exists
  // for this project we have considered  user-email to be the user-name (userid)
    const authenticate_user = async (email, password, done) => {
    const user = getUserByEmail(email)

    //case-1 if no such required user is found
    if (user == null) {
      return done(null, false, { message: 'No user with that email' })
    }
    //case-2 if a user is found
    try
     {
      //  case-2-a input password matches
      if (await bcrypt.compare(password, user.password)) 
      {
        return done(null, user)
      } 
      // case-2-b input password does not match
      else 
      {
        return done(null, false, { message: 'Input password incorrect' })
      }
    } 

    //case-3 some error has occured
    catch (error) 
    {
      return done(error)
    }
  }
  
  // here the authentication strategy is simple, it checks whether the user is found or not in local array named "users"
  // if a user is found , it simply checks the password input and the hashed password match or not
  passport.use(new User_Strategy({ usernameField: 'email' }, authenticate_user))

  // maintain user id of authenticated users 
  // it sends only user id
  passport.serializeUser((user, done) => done(null, user.id))

  //deserialize takes an id and returns a user
  passport.deserializeUser((id, done) => {
    return done(null, getUserById(id))
  })
}

module.exports = begin_authentication