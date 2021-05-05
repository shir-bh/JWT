import Joi from "joi";

export const schema_insert = Joi.object({
  first_name: Joi.string().min(3).max(30).required(),
  last_name: Joi.string().min(3).max(30).required(),
  email: Joi.string()
    .pattern(new RegExp("^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$"))
    .required(),
});

export const schema_update = Joi.object({
  first_name: Joi.string().min(3).max(30),
  last_name: Joi.string().min(3).max(30),
  email: Joi.string().pattern(new RegExp("^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$")),
});

//   "id": 1,
//   "first_name": "Kalinda",
//   "last_name": "Watchorn",
//   "email": "kwatchorn0@upenn.edu",
//   "gender": "Genderqueer",
//   "ip_address": "62.70.186.167"
