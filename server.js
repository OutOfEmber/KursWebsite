const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./Database/Database'); // Импортируем нашу базу из папки

const app = express();
app.use(express.json()); // Чтобы понимать JSON от пользователя

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