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
        console.log("⏳ Синхронизация базы данных...");
        
        // force: false — не удаляет данные. alter: true — обновляет структуру таблиц под модели.
        await sequelize.sync({ alter: false }); 
        
        console.log("✅ Таблицы успешно синхронизированы!");

        // --- ИНИЦИАЛИЗАЦИЯ ДАННЫХ (БЕЗ ДУБЛИКАТОВ) ---

        // Проверяем наличие магазинов
        const storeCount = await Store.count();
        if (storeCount === 0) {
            await Store.create({ 
                name: 'Главный Магазин', 
                address: 'ул. Пушкина, 1',
                image: 'https://vladivostok.unidoors.ru/upload/iblock/831/831a29f86014468f3a3f126f582f347e.jpg' // Можно сразу добавить фото
            });
            console.log("🏠 Начальный магазин добавлен");
        } else {
            console.log("ℹ️ Магазины уже существуют в базе, пропускаем создание");
        }

        // Проверяем наличие складов
        const storageCount = await Storage.count();
        if (storageCount === 0) {
            await Storage.create({ name: 'Основной Склад' });
            console.log("📦 Начальный склад добавлен");
        } else {
            console.log("ℹ️ Склады уже существуют в базе, пропускаем создание");
        }

        // --- ЗАПУСК СЕРВЕРА ---
        const PORT = 5000;
        app.listen(PORT, () => {
            console.log(`🚀 Сервер запущен: http://localhost:${PORT}`);
        });

    } catch (e) {
        console.error('❌ Ошибка при старте:', e);
    }
}

start();