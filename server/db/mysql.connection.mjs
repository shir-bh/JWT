import mysql from "mysql2/promise";
import log from "@ajar/marker";
let connection = await mysql.createConnection({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER_NAME,
  password: process.env.DB_USER_PASSWORD,
});
await connection.connect();
log.magenta("Connected to MySQL DB");
export default connection;
