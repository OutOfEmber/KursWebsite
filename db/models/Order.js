const { DataTypes } = require('sequelize');
const sequelize = require('../dbserver');

const Order = sequelize.define('Order', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    productCount: { type: DataTypes.INTEGER, defaultValue: 1 },
    totalPrice: DataTypes.DECIMAL(10, 2),
    status: { type: DataTypes.STRING, defaultValue: 'Новый' }
});
module.exports = Order;