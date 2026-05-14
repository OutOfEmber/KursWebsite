const { Sequelize, DataTypes } = require('sequelize');
const path = require('path');

const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: path.join(__dirname, 'db.sqlite') 
});

const User = sequelize.define('user', {
    email: { type: DataTypes.STRING, unique: true, allowNull: false },
    password: { type: DataTypes.STRING, allowNull: false },
    role: { type: DataTypes.STRING, defaultValue: 'USER' },
    fio: { type: DataTypes.STRING, allowNull: true }
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
    address: { type: DataTypes.STRING, defaultValue: "Адрес не указан" },
    image: { type: DataTypes.STRING }
});

const Storage = sequelize.define('storage', {
    name: { type: DataTypes.STRING, allowNull: false }
});

const Order = sequelize.define('order', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    userId: { type: DataTypes.INTEGER, allowNull: true }, 
    clientName: { type: DataTypes.STRING },
    items: { type: DataTypes.STRING, allowNull: false },
    totalPrice: { type: DataTypes.INTEGER, allowNull: false },
    status: { type: DataTypes.STRING, defaultValue: "Новый" }
});

// --- ВСЕ СВЯЗИ ТУТ ---
User.hasMany(Order, { foreignKey: 'userId' });
Order.belongsTo(User, { foreignKey: 'userId' });

// Один магазин может иметь много товаров
Store.hasMany(Door, { foreignKey: 'storeId' });
// Товар принадлежит конкретному магазину
Door.belongsTo(Store, { foreignKey: 'storeId' });

Storage.hasMany(Door);
Door.belongsTo(Storage);

module.exports = { sequelize, User, Door, Store, Storage, Order };