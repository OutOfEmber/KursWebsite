const express=require('express');
const sequelize=require('./db/dbserver.js');

const Door=require('./db/modules/Door.js')
const Storage=require('./db/modules/Storage.js');
const Store=require('./db/modules/Store.js');
const User=require('./db/modules/User.js');

const app=express();
app.use(express.json());

Storage.hasMany(Door,{foreignKey:'storageId'});
Door.belongsTo(Storage,{foreignKey:'storageId'});

Store.hasMany(Door,{foreignKey:'storeId'});
Door.belongsTo(Store,{foreignKey:'storeId'});
port=[];
for(let i=1;i<=3;i++){
    port.push(Math.floor(Math.random()*9000)+1000)
}
const randomPort=port[Math.floor(Math.random()*port.length)];
async function start() {
    try{
    await sequelize.authenticate();
    await sequelize.sync({force:false});
    console.log('БД синхронизирована');
    app.listen(randomPort,()=>console.log(`Сервер запущен на порте: ${randomPort}`))
    } catch(error){
        console.error('Ошибка запуска',error)
    }
}

start()