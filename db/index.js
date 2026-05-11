const express = require('express');
const path = require('path');
const sequelize = require('./dbserver.js');
const { Door, Storage, Store, User, Order } = require('./models.js'); 
const apiRouter = require('./router.js');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();

// Middlewares
app.use(cors()); // Это позволит Live Server (порту 5500) брать данные с порта 5000
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Раздача статических файлов (HTML, CSS, JS) из папки public
app.use(express.static(path.join(__dirname, 'public')));

// Настройка связей (Associations) [cite: 14]
Storage.hasMany(Door, { foreignKey: 'storageId' });
Door.belongsTo(Storage, { foreignKey: 'storageId' });

Store.hasMany(Door, { foreignKey: 'storeId' });
Door.belongsTo(Store, { foreignKey: 'storeId' });

User.hasMany(Order, { foreignKey: 'userId' });
Order.belongsTo(User, { foreignKey: 'userId' });

Door.hasMany(Order, { foreignKey: 'doorId' });
Order.belongsTo(Door, { foreignKey: 'doorId' });

// Подключение API роутера
app.use('/api', apiRouter);

// Определение порта (ваша логика с рандомным портом) 
// const ports = [];
// for (let i = 1; i <= 3; i++) {
//     ports.push(Math.floor(Math.random() * 9000) + 1000);
// }
// const randomPort = ports[Math.floor(Math.random() * ports.length)];
const randomPort=5000;

async function start() {
    try {
        // Проверка подключения к БД [cite: 15]
        await sequelize.authenticate();
        
        // Синхронизация моделей [cite: 16]
        await sequelize.sync({ force: false });
        console.log('БД успешно синхронизирована');
        const adminExists = await User.findOne({ where: { role: 'admin' } });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('admin_password', 10);
            await User.create({
                FIO: 'Главный Админ',
                email: 'admin@test.com',
                password: hashedPassword,
                role: 'admin'
            });
            console.log('Создан аккаунт администратора по умолчанию');
        }

        app.listen(randomPort, () => {
            console.log(`Сервер запущен на http://localhost:${randomPort}`);
            console.log(`API доступно по адресу http://localhost:${randomPort}/api`);
        });
    } catch (error) {
        console.error('Ошибка при запуске сервера:', error);
    }
}
start();