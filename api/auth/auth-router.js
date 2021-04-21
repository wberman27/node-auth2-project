const router = require("express").Router();
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { jwtSecret } = require("../secrets"); // use this secret!
const Users = require('../users/users-model')

router.post("/register", validateRoleName, (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  let user = req.body;

  const hash = bcrypt.hashSync(user.password, 8)
  user.password = hash
  
  Users.add(user)
  .then(addedUser =>{
    res.status(201).json(addedUser)
  })
  .catch(next)

});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  let {username, password} = req.body;

  Users.findBy({username})
  .then(([user]) =>{
    if(user && bcrypt.compareSync(password, user.password)){
      const token = makeToken(user)

      res.status(200).json({message: `${username} is back!`, token})
    }else{
      res.status(401).json({message: 'Invalid credentials'})
    }
  })
  .catch(next)
});

function makeToken(user){
  const payload = {
    subject: user.id,
    username: user.username,
    role: user.role_name,
  }
  const options = {
    expiresIn: "120s"
  };
  return jwt.sign(payload, jwtSecret, options);
}

module.exports = router;
