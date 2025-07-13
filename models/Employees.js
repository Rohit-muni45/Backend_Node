const mongoose = require('mongoose');

const employeeSchema = new mongoose.Schema({
  id: Number,
  name: String,
  email: String,
  location: String,
  age: Number,
  phoneNumber: String,
  role: String,
  company: String,
  image: String
},
    { collection: "Employess"}
)

const Employee = mongoose.model("Employee", employeeSchema);

module.exports = Employee;