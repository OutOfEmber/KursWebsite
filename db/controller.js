const { User, Door, Store, Storage, Order } = require('./models.js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const SECRET_KEY = "SECRET_CODE_2026";

const generateToken = (id, role) => {
    return jwt.sign({ id, role }, SECRET_KEY, { expiresIn: '24h' });
};

const createBaseController = (Model) => ({
    async getAll(req, res) {
        try {
            const data = await Model.findAll();
            res.json(data);
        } catch (e) { res.status(500).json({ error: e.message }); }
    },
    async create(req, res) {
        try {
            // Sequelize создаст запись из полей в req.body
            const data = await Model.create(req.body);
            res.status(201).json(data);
        } catch (e) { res.status(400).json({ error: "Ошибка создания: " + e.message }); }
    },
    async delete(req, res) {
        try {
            await Model.destroy({ where: { id: req.params.id } });
            res.json({ message: "Успешно удалено" });
        } catch (e) { res.status(400).json({ error: e.message }); }
    }
});

const authController = {
    async registration(req, res) {
        try {
            const { email, password, adminCode } = req.body;
            const candidate = await User.findOne({ where: { email } });
            if (candidate) return res.status(400).json({ error: "Email занят" });

            const hashPassword = await bcrypt.hash(password, 10);
            const role = adminCode === 'SECRET' ? 'ADMIN' : 'USER';
            
            const user = await User.create({ email, password: hashPassword, role });
            const token = generateToken(user.id, user.role);
            res.status(201).json({ token, role: user.role, id: user.id });
        } catch (e) { res.status(500).json({ error: e.message }); }
    },
    async login(req, res) {
        try {
            const { email, password } = req.body;
            const user = await User.findOne({ where: { email } });
            if (!user || !bcrypt.compareSync(password, user.password)) {
                return res.status(401).json({ error: "Неверный логин или пароль" });
            }
            const token = generateToken(user.id, user.role);
            res.json({ token, role: user.role, id: user.id });
        } catch (e) { res.status(500).json({ error: e.message }); }
    }
};

module.exports = {
    authController,
    doorController: createBaseController(Door),
    storeController: createBaseController(Store),
    orderController: createBaseController(Order),
    storageController: createBaseController(Storage)
};