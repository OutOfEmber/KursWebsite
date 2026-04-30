const { DataTypes } = require('sequelize');
const sequelize=require('../dbserver.js');
const Store=require('./Store.js');
const Storage=require('./Storage.js');

const Door = sequelize.define('Door',{
    id:{type:DataTypes.INTEGER, primaryKey:true, autoIncrement:true},
    name:DataTypes.STRING,
    material:DataTypes.STRING,
    doorType:DataTypes.STRING,
    price:DataTypes.DECIMAL(10,2),
    storeId:{type:DataTypes.INTEGER, references:{model:Store,key:'id'}},
    storageId:{type:DataTypes.INTEGER, references:{model:Storage,key:'id'}}
});

module.exports = Door;