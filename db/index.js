const express = require('express');
const cors = require('cors');
const path = require('path');
const { sequelize, Store, Storage } = require('./models');
const router = require('./router');

const app = express();
app.use(cors());
app.use(express.json());

// Подключаем роутер ко всем путям начинающимся с /api
app.use('/api', router);

async function start() {
    try {
        console.log("Синхронизация базы данных...");
        
        // ВНИМАНИЕ: force: true удалит старые данные, но зато создаст все нужные колонки (address и т.д.)
        // После ОДНОГО успешного запуска поменяй обратно на { alter: true }
        await sequelize.sync({ alter: true }); 
        
        console.log("Таблицы успешно созданы!");

        // Создаем начальные данные, чтобы сайт не был пустым
        await Store.create({ name: 'Главный Магазин', address: 'ул. Пушкина, 1' });
        await Storage.create({ name: 'Основной Склад' });

        const PORT = 5000;
        app.listen(PORT, () => {
            console.log(`🚀 Сервер запущен: http://localhost:${PORT}`);
        });
    } catch (e) {
        console.error('❌ Ошибка при старте:', e);
    }
}

start(); // ЗАПУСКАЕМ СЕРВЕР