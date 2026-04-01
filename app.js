'use strict';

const helpTexts = {
    entropy: "Информационная энтропия Шеннона. Чем выше, тем сложнее подобрать пароль перебором.",
    expectation: "Среднее значение кодов символов. Позволяет судить о центрировании выборки.",
    dispersion: "Мера разброса значений. Высокая дисперсия говорит о хаотичности и качестве случайности."
};

const el = {
    tabs: document.querySelectorAll('.tab-btn'),
    contents: document.querySelectorAll('.tab-content'),
    settingsBtn: document.getElementById('openSettings'),
    closeSettings: document.getElementById('closeSettings'),
    panel: document.getElementById('settingsPanel'),
    themeSelect: document.getElementById('themeSelect'),
    fontSlider: document.getElementById('fontSlider'),
    opacitySlider: document.getElementById('opacitySlider'),
    passResult: document.getElementById('passwordResult'),
    btnGenerate: document.getElementById('btnGenerate')
};

// --- ТАБЫ И НАСТРОЙКИ ---

el.tabs.forEach(tab => {
    tab.addEventListener('click', () => {
        el.tabs.forEach(t => t.classList.remove('active'));
        el.contents.forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById(`tab-${tab.dataset.tab}`).classList.add('active');
        
        if(tab.dataset.tab === 'analysis') runAnalysis();
    });
});

el.settingsBtn.onclick = () => el.panel.classList.add('open');
el.closeSettings.onclick = () => el.panel.classList.remove('open');

el.themeSelect.onchange = (e) => {
    document.body.className = e.target.value === 'default' ? '' : `theme-${e.target.value}`;
};

el.fontSlider.oninput = (e) => {
    document.documentElement.style.setProperty('--base-font', e.target.value + 'px');
};

el.opacitySlider.oninput = (e) => {
    document.documentElement.style.setProperty('--bg-card', `rgba(15, 23, 42, ${e.target.value/100})`);
};

document.addEventListener('click', (e) => {
    if(e.target.classList.contains('tip')) {
        alert(helpTexts[e.target.dataset.tip]);
    }
});

// --- ГЕНЕРАЦИЯ (ТВОЙ ОСНОВНОЙ КОД) ---

function getCharset() {
    let set = '';
    if (document.getElementById('useUpper').checked) set += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (document.getElementById('useLower').checked) set += 'abcdefghijklmnopqrstuvwxyz';
    if (document.getElementById('useDigits').checked) set += '0123456789';
    if (document.getElementById('useSpecial').checked) set += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    return set;
}

el.btnGenerate.onclick = () => {
    const len = document.getElementById('passLen').value;
    const charset = getCharset();
    const algo = document.getElementById('algoSelect').value;
    let pass = '';

    if (!charset) return alert("Выберите хотя бы один набор символов!");

    if (algo === 'lcg') {
        let seed = Date.now();
        for (let i = 0; i < len; i++) {
            seed = (1664525 * seed + 1013904223) % Math.pow(2, 32);
            pass += charset[seed % charset.length];
        }
    } else {
        const array = new Uint32Array(len);
        window.crypto.getRandomValues(array);
        for (let i = 0; i < len; i++) {
            pass += charset[array[i] % charset.length];
        }
    }

    el.passResult.value = pass;
    updateStrength(pass);
};

// --- АНАЛИЗ ---

function runAnalysis() {
    const pass = el.passResult.value;
    if(!pass) return;

    const codes = [...pass].map(c => c.charCodeAt(0));
    
    // Расчет энтропии
    const freq = {};
    codes.forEach(c => freq[c] = (freq[c] || 0) + 1);
    let entropy = 0;
    Object.values(freq).forEach(f => {
        let p = f / pass.length;
        entropy -= p * Math.log2(p);
    });

    document.getElementById('entropyVal').textContent = entropy.toFixed(2);
    // Тут вызов твоих графиков Chart.js...
    console.log("Анализ выполнен для:", pass);
}

function updateStrength(pass) {
    const score = Math.min(pass.length * 4, 100);
    const bar = document.getElementById('strengthBar');
    bar.style.width = score + '%';
    bar.style.background = score < 40 ? '#ef4444' : score < 75 ? '#fbbf24' : '#10b981';
    document.getElementById('strengthText').textContent = score < 40 ? 'Слабый' : score < 75 ? 'Средний' : 'Очень сильный';
}
