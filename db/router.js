const express = require('express');
const router = express.Router();
const { User, Door, Store, Storage, Order } = require('./models');

// --- 1. АВТОРИЗАЦИЯ И ПОЛЬЗОВАТЕЛИ ---
router.post('/user/registration', async (req, res) => {
    try {
        const { email, password, role } = req.body;
        // Принудительно сохраняем роль в верхнем регистре для стабильности
        const user = await User.create({ 
            email, 
            password, 
            role: role ? role.toUpperCase() : 'USER' 
        });
        res.json({ token: "fake-jwt-token", role: user.role });
    } catch (e) {
        res.status(500).json({ error: "Ошибка регистрации: " + e.message });
    }
});

router.post('/user/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ where: { email, password } });
        if (!user) return res.status(404).json({ error: "Пользователь не найден" });
        
        // Отправляем роль всегда в верхнем регистре
        res.json({ 
            token: "fake-jwt-token", 
            role: user.role ? user.role.toUpperCase() : 'USER' 
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// --- 2. СПЕЦИАЛЬНЫЕ РОУТЫ ДЛЯ ДАННЫХ (с джоинами) ---

// Получение дверей вместе со складом и магазином (важно для админки!)
router.get('/doors', async (req, res) => {
    try {
        const data = await Door.findAll({ include: [Store, Storage] });
        res.json(data);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Роут для заказов (POST от пользователя)
router.post('/orders', async (req, res) => {
    try {
        const { items, totalPrice, comment } = req.body;
        const order = await Order.create({ items, totalPrice, comment });
        res.json(order);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// --- 3. УНИВЕРСАЛЬНЫЕ РОУТЫ (для остального в админке) ---

// Общий GET для всех типов
router.get('/:type', async (req, res) => {
    try {
        const models = { 
            users: User, 
            doors: Door, 
            stores: Store, 
            storages: Storage, 
            orders: Order 
        };
        const Model = models[req.params.type];
        if (!Model) return res.status(404).json({ error: "Таблица не найдена" });
        
        const data = await Model.findAll();
        res.json(data);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Общий POST (создание из админки)
router.post('/:type', async (req, res) => {
    try {
        const models = { users: User, doors: Door, stores: Store, storages: Storage };
        const Model = models[req.params.type];
        const newItem = await Model.create(req.body);
        res.json(newItem);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Общий PUT (редактирование из админки)
router.put('/:type/:id', async (req, res) => {
    try {
        const models = { users: User, doors: Door, stores: Store, storages: Storage, orders: Order };
        const Model = models[req.params.type];
        await Model.update(req.body, { where: { id: req.params.id } });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Общий DELETE (удаление из админки)
router.delete('/:type/:id', async (req, res) => {
    try {
        const models = { users: User, doors: Door, stores: Store, storages: Storage, orders: Order };
        await models[req.params.type].destroy({ where: { id: req.params.id } });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

module.exports = router;