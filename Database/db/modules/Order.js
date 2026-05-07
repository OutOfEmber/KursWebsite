const { DataTypes } = require('sequelize')
const sequelize=require('../dbserver.js')

const Order=sequelize.define('Order',{
    id:{type:DataTypes.INTEGER,primaryKey:true,autoIncrement:true},
    productCount:DataTypes.INTEGER,
    totalPrice:DataTypes.DECIMAL(10,2)
});

module.exports = Order;