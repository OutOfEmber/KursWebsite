const User = require('./User');
const Door = require('./Door');
const Order = require('./Order');
const Storage = require('./Storage');
const Store = require('./Store');

// Связи: Дверь привязана к складу и магазину
Storage.hasMany(Door, { foreignKey: 'storageId' });
Door.belongsTo(Storage, { foreignKey: 'storageId' });

Store.hasMany(Door, { foreignKey: 'storeId' });
Door.belongsTo(Store, { foreignKey: 'storeId' });

// Связи: Заказы привязаны к пользователю и конкретной двери
User.hasMany(Order, { foreignKey: 'userId' });
Order.belongsTo(User, { foreignKey: 'userId' });

Door.hasMany(Order, { foreignKey: 'doorId' });
Order.belongsTo(Door, { foreignKey: 'doorId' });

module.exports = { User, Door, Order, Storage, Store };