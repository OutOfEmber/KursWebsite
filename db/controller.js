const { Door, User, Storage, Store } = require('./models.js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const SECRET_KEY = "SUPER_SECRET_KEY_2026";

const authController = {
    async register(req, res) {
        try {
            const { FIO, email, password, adminCode } = req.body;
            const hashedPassword = await bcrypt.hash(password, 10);
            const role = adminCode === '123' ? 'admin' : 'customer';
            await User.create({ FIO, email, password: hashedPassword, role });
            res.status(201).json({ message: "Успешно зарегистрирован!", role });
        } catch (e) { res.status(500).json({ error: e.message }); }
    },
    async login(req, res) {
        try {
            const { email, password } = req.body;
            const user = await User.findOne({ where: { email } });
            if (!user || !(await bcrypt.compare(password, user.password))) {
                return res.status(401).json({ error: "Неверные данные" });
            }
            const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: '24h' });
            res.json({ token, role: user.role, fio: user.FIO });
        } catch (e) { res.status(500).json({ error: e.message }); }
    }
};

const doorController = {
    async getAll(req, res) {
        const items = await Door.findAll({ include: { all: true } });
        res.json(items);
    },
    async create(req, res) {
        try {
            const newItem = await Door.create(req.body);
            res.status(201).json(newItem);
        } catch (e) { res.status(400).json({ error: e.message }); }
    },
    async delete(req, res) {
        await Door.destroy({ where: { id: req.params.id } });
        res.json({ message: "Удалено" });
    }
};

module.exports = { authController, doorController };