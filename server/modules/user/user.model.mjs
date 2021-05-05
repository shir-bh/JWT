import mongoose from 'mongoose'
const { Schema, model } = mongoose

const UserSchema = new Schema({
    first_name : { type : String, required : [true,'First name is really important'] },
    last_name  : { type : String, required : true },
    email      : { type : String, required : true, unique : true},
    password   : { type : String, required : true },
    phone      : {
        type: String,
        validate: {
          validator: function(v) {
            return /\d{3}-\d{3}-\d{4}/.test(v);
          },
          message: props => `${props.value} is not a valid phone number!`
        },
        required: [true, 'User phone number required']
      }
}, {timestamps:true});
  
export default model('user',UserSchema);