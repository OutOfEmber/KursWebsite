const express = require('express');
const router = express.Router();
const { User, Door, Store, Storage, Order } = require('./models');

// ПОЛУЧЕНИЕ ДАННЫХ
router.get('/:type', async (req, res) => {
    try {
        const models = { users: User, doors: Door, stores: Store, storages: Storage, orders: Order };
        const Model = models[req.params.type];
        if (!Model) return res.status(404).send('Not found');
        
        // Для дверей подтягиваем инфо о магазине и складе
        const include = req.params.type === 'doors' ? [Store, Storage] : [];
        const data = await Model.findAll({ include });
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// СОЗДАНИЕ (POST)
router.post('/:type', async (req, res) => {
    try {
        const models = { users: User, doors: Door, stores: Store, storages: Storage, orders: Order };
        const Model = models[req.params.type];
        const newItem = await Model.create(req.body);
        res.json(newItem);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// РЕДАКТИРОВАНИЕ (PUT) - ТО ЧТО МЫ ЧИНИЛИ
router.put('/:type/:id', async (req, res) => {
    try {
        const { type, id } = req.params;
        const models = { users: User, doors: Door, stores: Store, storages: Storage, orders: Order };
        const Model = models[type];
        
        await Model.update(req.body, { where: { id } });
        const updated = await Model.findByPk(id);
        res.json(updated);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// УДАЛЕНИЕ (DELETE)
router.delete('/:type/:id', async (req, res) => {
    try {
        const models = { users: User, doors: Door, stores: Store, storages: Storage, orders: Order };
        await models[req.params.type].destroy({ where: { id: req.params.id } });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

module.exports = router;