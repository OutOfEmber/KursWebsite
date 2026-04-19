const express = require('express');
const cors = require('cors'); // Импортируем
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./Database/Database');

const app = express();

app.use(cors()); // Разрешаем запросы от фронтенда
app.use(express.json()); // Читаем JSON в теле запроса

const SECRET_KEY = 'SECRET_KEY_123';

// Маршрут регистрации
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hash = await bcrypt.hash(password, 10); 
    
    try {
        const stmt = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)');
        stmt.run(username, hash);
        res.send("Пользователь создан");
    } catch (err) {
        res.status(400).send("Ошибка: такой логин уже занят");
    }
});

// Функция-прослойка для проверки, залогинен ли пользователь
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Достаем токен из "Bearer <TOKEN>"

    if (!token) return res.sendStatus(401); // Если токена нет - от ворот поворот

    jwt.verify(token, 'SECRET_KEY_123', (err, user) => {
        if (err) return res.sendStatus(403); // Если токен неверный или просрочен
        req.user = user;
        next(); // Всё ок, идем дальше
    });
};

// Пример защищенного маршрута
app.get('/me', authenticateToken, (req, res) => {
    const user = db.prepare('SELECT id, username FROM users WHERE id = ?').get(req.user.id);
    res.json(user);
});

// Маршрут входа
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    
    if (!user) return res.status(404).send("Пользователь не найден");

    const isValid = await bcrypt.compare(password, user.password_hash);
    
    if (isValid) {
        const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    } else {
        res.status(401).send("Неверный пароль");
    }
});

app.listen(3000, () => {
    console.log('Сервер запущен: http://localhost:3000');
});