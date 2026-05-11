const { DataTypes } = require('sequelize')
const sequelize=require('../dbserver.js')

const Storage=sequelize.define('Storage',{
    id:{type:DataTypes.INTEGER,primaryKey:true,autoIncrement:true},
    name:DataTypes.STRING,
    adress:DataTypes.STRING,
    phone:DataTypes.STRING
});

module.exports = Storage;