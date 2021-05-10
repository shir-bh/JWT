import bcrypt from "bcryptjs";
import express from "express";
import log from "@ajar/marker";
import raw from "../../middleware/route.async.wrapper.mjs";
import connection from "../../db/mysql.connection.mjs";
import passport from "passport";
import jwt from "jsonwebtoken";
import ms from "ms";
import cookieParser from "cookie-parser";

import {
  verify_token,
  false_response,
  tokenize,
} from "../../middleware/auth.middleware.mjs";

const {
  CLIENT_ORIGIN,
  APP_SECRET,
  ACCESS_TOKEN_EXPIRATION,
  REFRESH_TOKEN_EXPIRATION,
} = process.env;

const router = express.Router();
router.use(cookieParser());
router.use(express.json());

const githubAuth = passport.authenticate("github", { session: false });
router.get("/github", githubAuth);

router.get("/github/callback", githubAuth, (req, res) => {
  const user = {
    name: req.user.username,
    photo: req.user.photos[0].value,
  };
  redirect_tokens(req, res, user);
});

function redirect_tokens(req, res, user) {
  const access_token = jwt.sign(
    { id: req.user.id, some: "other value" },
    APP_SECRET,
    {
      expiresIn: ACCESS_TOKEN_EXPIRATION, // expires in 1 minute
    }
  );
  const refresh_token = jwt.sign(
    { id: req.user.id, profile: JSON.stringify(user) },
    APP_SECRET,
    {
      expiresIn: REFRESH_TOKEN_EXPIRATION, // expires in 60 days... long-term...
    }
  );
  res.cookie("refresh_token", refresh_token, {
    maxAge: ms("60d"), //60 days
    httpOnly: true,
  });
  res.redirect(
    `${CLIENT_ORIGIN}?token=${access_token}&profile=${encodeURIComponent(
      JSON.stringify(user)
    )}`
  );
}

router.get("/get-access-token", async (req, res) => {
  //get refresh_token from client - req.cookies
  const { refresh_token } = req.cookies;

  console.log({ refresh_token });

  if (!refresh_token)
    return res.status(403).json({
      status: "Unauthorized",
      payload: "No refresh_token provided.",
    });

  try {
    // verifies secret and checks expiration
    const decoded = await jwt.verify(refresh_token, APP_SECRET);
    console.log({ decoded });

    const { id, profile } = decoded;

    const access_token = jwt.sign({ id, some: "other value" }, APP_SECRET, {
      expiresIn: ACCESS_TOKEN_EXPIRATION, //expires in 1 minute
    });
    res.status(200).json({ access_token, profile });
  } catch (err) {
    console.log("error: ", err);
    return res.status(401).json({
      status: "Unauthorized",
      payload: "Unauthorized - Failed to verify refresh_token.",
    });
  }
});
export const verifyAuth = async (req, res, next) => {
  try {
    // check header or url parameters or post parameters for token
    const access_token = req.headers["x-access-token"];

    if (!access_token)
      return res.status(403).json({
        status: "Unauthorized",
        payload: "No token provided.",
      });

    // verifies secret and checks exp
    const decoded = await jwt.verify(access_token, APP_SECRET);

    // if everything is good, save to request for use in other routes
    req.user_id = decoded.id;
    next();
  } catch (error) {
    return res.status(401).json({
      status: "Unauthorized",
      payload: "Unauthorized - Failed to authenticate token.",
    });
  }
};
// CREATES A NEW USER
router.post(
  "/",
  raw(async (req, res) => {
    log.obj(req.body, "create a user, req.body:");
    const sql = `INSERT INTO users SET ?`;
    const [result] = await db.query(sql, req.body);
    const ok = { status: 200, message: `User Created successfully` };
    const fail = { status: 404, message: `Error in creating user ` };
    const { status, message } = result.affectedRows ? ok : fail;
    res.status(status).json({ message, result });
  })
);

router.post(
  "/register",
  raw(async (req, res) => {
    log.obj(req.body, "register, req.body:");

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    log.info("hashedPassword:", hashedPassword);
    const user_data = {
      ...req.body,
      password: hashedPassword,
    };
    // create a user
    // const created_user = await user_model.create(user_data);
    const [user] = await connection.query(
      `INSERT INTO users (first_name, last_name, email,password) VALUES ("${user_data.first_name}", "${user_data.last_name}", "${user_data.email}","${user_data.password}");`
    );
    console.log(user.id);
    const [[created_user]] = await connection.query(
      `SELECT * FROM users WHERE email= '${req.body.email}';`
    );
    log.obj(created_user, "register, created_user:");

    // create a token
    const token = tokenize(created_user._id);
    log.info("token:", token);

    return res.status(200).json({
      auth: true,
      token,
      user: created_user,
    });
  })
);

router.post(
  "/login",
  raw(async (req, res) => {
    //extract from req.body the credentials the user entered
    const { email, password } = req.body;

    //look for the user in db by email

    const user_current = await connection.query(
      `SELECT * FROM users WHERE email="${email}";`
    );
    const user = user_current[0][0];
    // const user = await user_model.findOne({ email });
    //if no user found...
    if (!user)
      return res
        .status(401)
        .json({ ...false_response, message: "wrong email or password" });

    // check if the password is valid
    const password_is_valid = await bcrypt.compare(password, user.password);
    console.log(password);
    console.log(user.password);
    console.log(password_is_valid);
    if (!password_is_valid)
      return res
        .status(401)
        .json({ ...false_response, message: "wrong email or password" });

    // if user is found and password is valid
    // create a fresh new token
    const token = tokenize(user.id);

    // return the information including token as JSON
    return res.status(200).json({
      auth: true,
      token,
      user: user,
    });
  })
);

router.get(
  "/logout",
  raw(async (req, res) => {
    req.logout();
    res.clearCookie("refresh_token");
    return res.status(200).json(false_response);
  })
);
router.get(
  "/me",
  verify_token,
  raw(async (req, res) => {
    const [rows, fields] = await connection.query(
      `SELECT * FROM data WHERE id="${req.user_id}"; `
    );
    if (rows.length === 0)
      return res.status(404).json({ message: "No user found." });
    res.status(200).json(rows);
  })
);

export default router;
