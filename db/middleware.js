const jwt = require('jsonwebtoken');
const SECRET_KEY = "SUPER_SECRET_KEY_2026";

module.exports = function(role) {
    return function (req, res, next) {
        try {
            const token = req.headers.authorization.split(' ')[1]; // Bearer <token>
            if (!token) return res.status(401).json({ message: "Не авторизован" });

            const decoded = jwt.verify(token, SECRET_KEY);
            if (role && decoded.role !== role) {
                return res.status(403).json({ message: "Нет доступа" });
            }
            req.user = decoded;
            next();
        } catch (e) { res.status(401).json({ message: "Ошибка авторизации" }); }
    };
};