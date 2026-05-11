const { Sequelize, DataTypes } = require('sequelize');
const path = require('path');

const sequelize = new Sequelize({
    dialect: 'sqlite',
    // Оставляем твой путь к базе
    storage: path.join(__dirname, 'db.sqlite') 
});

const User = sequelize.define('user', {
    email: { type: DataTypes.STRING, unique: true, allowNull: false },
    password: { type: DataTypes.STRING, allowNull: false },
    role: { type: DataTypes.STRING, defaultValue: 'USER' }
});

const Door = sequelize.define('door', {
    name: { type: DataTypes.STRING, allowNull: false },
    doorType: { type: DataTypes.STRING, allowNull: true }, 
    price: { type: DataTypes.INTEGER, allowNull: false },
    material: { type: DataTypes.STRING },
    image: { type: DataTypes.STRING }
});

const Store = sequelize.define('store', {
    name: { type: DataTypes.STRING, allowNull: false },
    address: { type: DataTypes.STRING, allowNull: true } // Разрешаем пустоту для старых записей
});

const Storage = sequelize.define('storage', {
    name: { type: DataTypes.STRING, allowNull: false }
});

const Order = sequelize.define('order', {
    items: { type: DataTypes.TEXT, allowNull: false }, 
    totalPrice: { type: DataTypes.INTEGER, allowNull: false },
    comment: { type: DataTypes.STRING },
    status: { type: DataTypes.STRING, defaultValue: 'Новый' }
});

Store.hasMany(Door);
Door.belongsTo(Store);
Storage.hasMany(Door);
Door.belongsTo(Storage);

module.exports = { sequelize, User, Door, Store, Storage, Order };