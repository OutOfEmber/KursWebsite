const { User, Door, Store, Storage, Order } = require('./models.js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const SECRET_KEY = "SECRET_CODE_2026";

const generateToken = (id, role) => {
    return jwt.sign({ id, role }, SECRET_KEY, { expiresIn: '24h' });
};

// Базовая логика для всех контроллеров
const createBaseController = (Model) => ({
    async getAll(req, res) {
        try {
            const data = await Model.findAll();
            res.json(data);
        } catch (e) { res.status(500).json({ error: e.message }); }
    },
    async create(req, res) {
        try {
            const data = await Model.create(req.body);
            res.status(201).json(data);
        } catch (e) { res.status(400).json({ error: e.message }); }
    },
    async delete(req, res) {
        try {
            await Model.destroy({ where: { id: req.params.id } });
            res.json({ message: "Удалено" });
        } catch (e) { res.status(400).json({ error: e.message }); }
    }
});

const doorController = {
    ...createBaseController(Door),
    async getAll(req, res) {
        try {
            const doors = await Door.findAll({ include: [Store, Storage] });
            res.json(doors);
        } catch (e) { res.status(500).json({ error: e.message }); }
    }
};

const orderController = {
    ...createBaseController(Order),
    async create(req, res) {
        try {
            const { items, totalPrice, comment } = req.body;
            // Если items пришел как строка, оставляем как есть, если как массив — сериализуем
            const finalItems = typeof items === 'string' ? items : JSON.stringify(items);
            
            const order = await Order.create({
                items: finalItems,
                totalPrice: parseFloat(totalPrice),
                comment,
                userId: req.user.id
            });
            res.status(201).json(order);
        } catch (e) { 
            console.error("Ошибка создания заказа:", e);
            res.status(400).json({ error: e.message }); 
        }
    }
};

const authController = {
    async register(req, res) {
        try {
            const { FIO, email, password, adminCode } = req.body;
            const hashPassword = await bcrypt.hash(password, 10);
            const role = adminCode === '123' ? 'admin' : 'customer';
            await User.create({ FIO, email, password: hashPassword, role });
            res.status(201).json({ message: "Регистрация успешна" });
            const candidate = await User.findOne({ where: { email } });
            if (candidate) {
            return res.status(400).json({ error: "Пользователь с таким Email уже существует" });
            }
            
        } catch (e) { res.status(500).json({ error: e.message }); }
    },
    async login(req, res) {
        try {
            const { email, password } = req.body;
            const user = await User.findOne({ where: { email } });
            if (!user || !bcrypt.compareSync(password, user.password)) {
                return res.status(401).json({ error: "Неверные данные" });
            }
            const token = generateToken(user.id, user.role);
            res.json({ token, role: user.role, fio: user.FIO });
        } catch (e) { res.status(500).json({ error: e.message }); }
    }
};

module.exports = {
    authController, // Убедитесь, что это имя совпадает с тем, что в router.js
    doorController,
    orderController,
    storeController: createBaseController(Store),
    storageController: createBaseController(Storage),
    userController: createBaseController(User)
};