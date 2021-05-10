import express from "express";
import morgan from "morgan";
import log from "@ajar/marker";
import cors from "cors";
import user_router from "./modules/user/user.router.mjs";
import { error_handler, not_found } from "./middleware/errors.handler.mjs";
import passport from "passport";
import passport_config from "./modules/auth/passport.config.mjs";
import auth_router, { verifyAuth } from "./modules/auth/auth.router.mjs";

const { PORT, HOST, DB_URI } = process.env;

const app = express();
app.use(express.json());
app.use(cors());
app.use(morgan("dev"));

passport_config();

app.use(passport.initialize());
app.use(passport.session());

// routing
app.use("/api/users", user_router);
app.use("/api/auth/", auth_router);
app.get("/api/protected", verifyAuth, (req, res) => {
  res.status(200).json({
    status: "OK",
    payload: `some sensitive data on user id ${req.user_id}`,
  });
});
// central error handling
app.use(error_handler);

//when no routes were matched...
app.use("*", not_found);

//start the express api server
(async () => {
  //connect to mongo db
  // await connect_db(DB_URI);
  await app.listen(PORT, HOST);
  log.magenta(`api is live on`, ` ✨ ⚡  http://${HOST}:${PORT} ✨ ⚡`);
})().catch(log.error);
