function syncAuthUI() {
    const role = localStorage.getItem('role');
    const userId = localStorage.getItem('userId'); // Теперь ориентируемся на ID
    
    const admLink = document.getElementById('adm-link');
    const ordersLink = document.getElementById('orders-link');
    const loginLink = document.getElementById('login-link');
    const logoutBtn = document.getElementById('logout-btn');
    const cartCount = document.getElementById('cart-count');

    if (userId) {
        // Пользователь авторизован
        if (loginLink) loginLink.style.display = 'none';
        if (logoutBtn) logoutBtn.style.display = 'block';
        if (ordersLink) ordersLink.style.display = 'block';

        // Админка только для ADMIN
        if (role === 'ADMIN' && admLink) {
            admLink.classList.remove('hidden');
            admLink.style.display = 'block';
        }
    } else {
        // Гость
        if (loginLink) loginLink.style.display = 'block';
        if (logoutBtn) logoutBtn.style.display = 'none';
        if (ordersLink) ordersLink.style.display = 'none';
        if (admLink) admLink.style.display = 'none';
    }

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