const express = require('express');
const cors = require('cors');
const { sequelize, Store, Storage } = require('./models');
const router = require('./router');

const app = express();
app.use(cors());
app.use(express.json());
app.use('/api', router);

async function start() {
    try {
        console.log("Подключение к базе данных...");
        // force: true пересоздаст таблицы (все старые данные удалятся!)
        await sequelize.sync({ force: false }); 
        
        console.log("Таблицы пересозданы успешно!");

        await Store.create({ name: 'Главный Магазин', address: 'ул. Пушкина, 1' });
        await Storage.create({ name: 'Основной Склад' });

        app.listen(5000, () => {
            console.log('🚀 Server started on http://localhost:5000');
        });
    } catch (e) {
        console.error('❌ Ошибка запуска:', e);
    }
}

// ВОТ ЭТА СТРОКА ОБЯЗАТЕЛЬНА:
start();