const { DataTypes } = require('sequelize')
const sequelize=require('../dbserver.js')

const Store=sequelize.define('Store',{
    id:{type:DataTypes.INTEGER,primaryKey:true,autoIncrement:true},
    name:DataTypes.STRING,
    adress:DataTypes.STRING,
    phone:DataTypes.STRING
});

module.exports = Store;