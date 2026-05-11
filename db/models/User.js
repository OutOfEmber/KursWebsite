const { DataTypes } = require('sequelize')
const sequelize=require('../dbserver.js');

const User = sequelize.define('User',{
    id:{type:DataTypes.INTEGER,primaryKey:true,autoIncrement:true},
    FIO:DataTypes.STRING,
    password:DataTypes.STRING,
    email:DataTypes.STRING,
    role:DataTypes.STRING
});

module.exports = User;