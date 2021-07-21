const { JWT_SECRET } = require("../secrets"); // use this secret!
const User = require("../users/users-model")
const jwt = require("jsonwebtoken")

const restricted = (req, res, next) => {
  const token = req.headers.authorization
  if (!token) {
    return next({
      status: 401,
      message: "Token required"
    })
  }
  jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
    if (err) {
      return next({
        status: 401,
        message: "Token invalid"
      })
    }
    req.decodedJwt = decodedToken
    next()
  })
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
}

const only = role_name => (req, res, next) => {
  const { decodedJwt } = req
  if(decodedJwt.role_name === role_name) {
    next()
  } else {
    next({
      status:403,
      message: "This is not for you"
    })
  }
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
}


const checkUsernameExists = async (req, res, next) => {
  const username = await User.findBy({username: req.body.username})
  if (!username) {
    return next({
      status: 401,
      message: "Invalid credentials"
    })
  }
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
}


const validateRoleName = async (req, res, next) => {
  const role_name = await User.findBy({role_name: req.body.role_name})
  if (role_name.length) {
    return role_name.length.trim()
  }
  if (!role_name || role_name === "") {
    return req.role_name = "student"
  }
  if (role_name === "admin") {
    return next({
      status: 422,
      message: "Role name can not be admin"
    })
  }
  if (role_name.length.trim() >= 32) {
    return next({
      status: 422,
      message: "Role name can not be longer than 32 chars"
    })
  }
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
