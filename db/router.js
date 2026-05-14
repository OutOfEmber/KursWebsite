const express = require('express');
const router = express.Router();
const { 
    authController, 
    doorController, 
    storeController, 
    orderController, 
    storageController 
} = require('./controller.js');

// Импортируем модели напрямую для универсальных методов админки
const { Door, Store, Storage, Order, User } = require('./models');

// --- 1. АВТОРИЗАЦИЯ ---
// Используем контроллер, так как там зашита логика хеширования паролей и JWT
router.post('/user/registration', authController.registration);
router.post('/user/login', authController.login);

// --- 2. ЗАКАЗЫ (Специальная логика) ---
// Эти пути должны идти ПЕРЕД универсальными /:type
router.get('/orders', orderController.getAll);
router.post('/orders', orderController.create); 

// --- 3. УНИВЕРСАЛЬНЫЕ МАРШРУТЫ ДЛЯ АДМИНКИ ---

// ГЕТ (Получение всех данных для таблиц)
router.get('/:type', async (req, res) => {
    try {
        const models = { 
            doors: Door, 
            stores: Store, 
            storages: Storage, 
            orders: Order, 
            users: User 
        };
        const Model = models[req.params.type];
        if (!Model) return res.status(404).json({ error: "Таблица не найдена" });
        
        const data = await Model.findAll();
        res.json(data);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ПОСТ (Создание из админки: дверей, складов и т.д.)
router.post('/:type', async (req, res) => {
    try {
        const models = { 
            doors: Door, 
            stores: Store, 
            storages: Storage 
        };
        const Model = models[req.params.type];
        if (!Model) return res.status(404).json({ error: "Таблица не найдена или защищена" });

        const newItem = await Model.create(req.body);
        res.json(newItem);
    } catch (e) {
        res.status(500).json({ error: "Ошибка при создании записи: " + e.message });
    }
});

// ПУТ (Редактирование из админки)
router.put('/:type/:id', async (req, res) => {
    try {
        const models = { 
            doors: Door, 
            stores: Store, 
            storages: Storage, 
            orders: Order 
        };
        const Model = models[req.params.type];
        if (!Model) return res.status(404).json({ error: "Таблица не найдена" });

        await Model.update(req.body, { where: { id: req.params.id } });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: "Ошибка при обновлении: " + e.message });
    }
});

// ДЕЛЕТЕ (Удаление)
// Обрабатывает и старый формат /api/doors/1 и новый /api/delete/doors/1
const deleteHandler = async (req, res) => {
    try {
        const models = { 
            doors: Door, 
            stores: Store, 
            storages: Storage, 
            orders: Order,
            users: User
        };
        const Model = models[req.params.type];
        if (!Model) return res.status(404).json({ error: "Таблица не найдена" });

        await Model.destroy({ where: { id: req.params.id } });
        res.json({ message: "Успешно удалено" });
    } catch (e) {
        res.status(500).json({ error: "Ошибка при удалении: " + e.message });
    }
};

router.delete('/:type/:id', deleteHandler);
router.delete('/delete/:type/:id', deleteHandler);

module.exports = router;