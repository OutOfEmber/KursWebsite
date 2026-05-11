// Функция для вставки общей шапки
function injectHeader() {
    const role = localStorage.getItem('role');
    const fio = localStorage.getItem('fio');
    const header = document.getElementById('header-placeholder') || document.querySelector('header');
    
    if (!header) return;

    header.className = "bg-white shadow-sm py-4 px-[5%] flex justify-between items-center sticky top-0 z-[100]";
    header.innerHTML = `
    <div class="logo font-bold text-2xl flex-shrink-0">INVISIBLE <span class="text-blue-600">LOFT</span></div>
    <nav class="flex items-center justify-end gap-6 flex-1">
        <a href="index.html" class="hover:text-blue-600">Главная</a>
        <a href="catalog.html" class="hover:text-blue-600">Каталог</a>
        <a href="stores.html" class="hover:text-blue-600">Магазины</a>
        <a href="about.html" class="hover:text-blue-600">О нас</a>
        <a href="cart.html" class="relative">🛒 <span id="cart-count" class="bg-red-500 text-white text-[10px] rounded-full px-1 absolute -top-2 -right-2">0</span></a>
        
        <div class="auth-btns ml-4 border-l pl-6 flex items-center gap-3">
            ${fio ? `
                <span class="text-sm font-bold text-slate-700 whitespace-nowrap">${fio}</span>
                ${role === 'admin' ? '<a href="admin.html" class="text-blue-600 text-sm font-bold hover:underline">Админка</a>' : ''}
                <button onclick="logout()" class="btn-outline btn-exit px-3 py-1 border border-red-200 text-red-500 rounded hover:bg-red-50 transition">Выйти</button>
            ` : `
                <button onclick="location.href='login.html'" class="btn-outline">Войти</button>
            `}
        </div>
    </nav>
`;
    updateCartCount();
}

function updateCartCount() {
    const cart = JSON.parse(localStorage.getItem('cart') || '[]');
    const el = document.getElementById('cart-count');
    if (el) el.innerText = cart.length;
}

function logout() {
    localStorage.clear();
    location.href = 'index.html';
}

window.onload = injectHeader;