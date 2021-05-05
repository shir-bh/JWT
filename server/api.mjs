import express from "express";
import morgan from "morgan";
import log from "@ajar/marker";
import cors from "cors";
import user_router from "./modules/user/user.router.mjs";
import auth_router from "./modules/auth/auth.router.mjs";
import { error_handler, not_found } from "./middleware/errors.handler.mjs";

const { PORT, HOST, DB_URI } = process.env;

const app = express();

// middlewares
app.use(cors());
app.use(morgan("dev"));

// routing
app.use("/api/users", user_router);
app.use("/api/auth", auth_router);

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
