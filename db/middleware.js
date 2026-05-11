const jwt = require('jsonwebtoken');
const SECRET_KEY = "SECRET_CODE_2026";

module.exports = (role) => {
    return (req, res, next) => {
        if (req.method === "OPTIONS") next();
        try {
            const token = req.headers.authorization.split(' ')[1];
            if (!token) return res.status(401).json({ message: "Не авторизован" });

            const decoded = jwt.verify(token, SECRET_KEY);
            // ВАЖНО: записываем данные юзера в запрос
            req.user = decoded; 

            if (role && decoded.role !== role) {
                return res.status(403).json({ message: "Нет доступа" });
            }
            next();
        } catch (e) {
            res.status(401).json({ message: "Не авторизован" });
        }
    };
};