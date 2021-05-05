/* 
  if there is an error thrown in the DB, asyncMiddleware
  will pass it to next() and express will handle the error */
import connection from "../../db/mysql.connection.mjs";
import raw from "../../middleware/route.async.wrapper.mjs";
import express from "express";
import log from "@ajar/marker";
import { schema_insert, schema_update } from "./user.validation.mjs";
const router = express.Router();

// parse json req.body on post routes
router.use(express.json());

router.post(
  "/",
  raw(async (req, res) => {
    const { error, value } = schema_insert.validate(req.body);
    if (error) {
      throw new Error(error);
    } else {
      console.log(req.body);
      const user_current = await connection.query(
        `INSERT INTO users (first_name, last_name, email) VALUES ("${req.body.first_name}", "${req.body.last_name}", "${req.body.email}");`
      );
      const user = await connection.query(
        `SELECT * FROM users WHERE id='${user_current.id}'`
      );
      res.status(200).json(user);
    }
  })
);

router.get(
  "/",
  raw(async (req, res) => {
    const users = await connection.query("SELECT * FROM users;");
    res.status(200).json(users);
  })
);

router.get(
  "/paginate/:page?/:items?",
  raw(async (req, res) => {
    log.obj(req.params, "get all users, req.params:");
    let { page = 0, items = 10 } = req.params;
    const users = await connection.query(
      `SELECT * FROM users LIMIT ${page * items},${items}`
    );
    res.status(200).json(users);
  })
);

// GETS A SINGLE USER
router.get(
  "/:id",
  raw(async (req, res) => {
    const user = await connection.query(
      `SELECT * FROM users WHERE id = ${req.params.id};`
    );
    res.status(200).json(user[0][0]);
  })
);

// // UPDATES A SINGLE USER
router.put(
  "/:id",
  raw(async (req, res) => {
    const result = schema_update.validate(req.body);
    if (result.error == null) {
      let updateString = `UPDATE users SET `;
      let updateArr = [];
      for (const field in req.body) {
        updateArr.push(`${field}="${req.body[field]}"`);
      }
      updateString = updateString + updateArr.join(", ");
      updateString = updateString + ` WHERE id=${req.params.id} `;
      console.log(updateString);
      const user = await connection.query(updateString);
      res.status(200).json(user);
    } else {
      throw new Error(result.error);
    }
  })
);

// DELETES A USER
router.delete(
  "/:id",
  raw(async (req, res) => {
    const user = connection.query(
      `DELETE FROM users WHERE id=${req.params.id}`
    );
    res.status(200).json(user);
  })
);

export default router;
