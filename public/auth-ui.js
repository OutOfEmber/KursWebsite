function syncAuthUI() {
    const token = localStorage.getItem('token');
    const role = localStorage.getItem('role');
    
    // Находим кнопки (они должны иметь эти ID во всех HTML)
    const admLink = document.getElementById('adm-link');
    const loginLink = document.getElementById('login-link');
    const logoutBtn = document.getElementById('logout-btn');
    const cartCount = document.getElementById('cart-count');

    // 1. Логика кнопок Вход / Выход / Админка
    if (token) {
        if (loginLink) loginLink.classList.add('hidden'); // Прячем "Вход"
        if (logoutBtn) logoutBtn.classList.remove('hidden'); // Показываем "Выйти"
        
        // Показываем админку только если роль ADMIN
        if (role && role.toUpperCase() === 'ADMIN') {
            if (admLink) admLink.classList.remove('hidden');
        } else {
            if (admLink) admLink.classList.add('hidden');
        }
    } else {
        if (loginLink) loginLink.classList.remove('hidden'); // Показываем "Вход"
        if (logoutBtn) logoutBtn.classList.add('hidden');    // Прячем "Выйти"
        if (admLink) admLink.classList.add('hidden');       // Прячем админку
    }

    // 2. Обновляем счетчик корзины
    if (cartCount) {
        const cart = JSON.parse(localStorage.getItem('cart') || '[]');
        cartCount.innerText = cart.length;
    }
}

function logout() {
    if (confirm('Выйти из профиля?')) {
        localStorage.removeItem('token');
        localStorage.removeItem('role');
        window.location.href = 'index.html';
    }
}

// Запускаем при загрузке страницы
document.addEventListener('DOMContentLoaded', syncAuthUI);