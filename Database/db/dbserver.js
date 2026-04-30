const {DataTypes,Sequelize} = require('sequelize');
const sequelize = new Sequelize({
    dialect:'sqlite',
    storage:'./db.sqlite',
    logging:true, 
});
module.exports = sequelize;