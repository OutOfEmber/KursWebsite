const express = require('express');
const router = express.Router();
const { authController, doorController } = require('./controller');
const checkRole = require('./middleware');

router.post('/auth/register', authController.register);
router.post('/auth/login', authController.login);

router.get('/doors', doorController.getAll);
router.post('/doors', checkRole('admin'), doorController.create);
router.delete('/doors/:id', checkRole('admin'), doorController.delete);

module.exports = router;