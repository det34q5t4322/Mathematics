'use strict';

// 1. ТЕКСТЫ ПОДСКАЗОК
const TIPS = {
  entropy: "Энтропия Шеннона (H): мера неопределенности. Чем выше значение, тем сложнее взломать пароль методом перебора (Brute-force).",
  math: "Математическое ожидание (E): среднее значение кодов символов. Показывает центр распределения символов в наборе данных.",
  disp: "Дисперсия (D): мера разброса значений вокруг среднего. Высокая дисперсия указывает на хаотичность и отсутствие паттернов."
};

// 2. СОСТОЯНИЕ ПРИЛОЖЕНИЯ
const state = {
  currentPassword: '',
  mouseEntropy: [],
  poolReady: false,
  charts: { freq: null, phase: null }
};

// 3. DOM ЭЛЕМЕНТЫ
const el = {
  tabs: document.querySelectorAll('.tab-btn'),
  pages: document.querySelectorAll('.tab-content'),
  panel: document.getElementById('settingsPanel'),
  btnOpen: document.getElementById('openSettings'),
  btnClose: document.getElementById('closeSettings'),
  passOut: document.getElementById('passOutput'),
  btnGen: document.getElementById('btnGenerate'),
  themeBtns: document.querySelectorAll('.theme-option'),
  fontSlider: document.getElementById('fontSlider'),
  opacitySlider: document.getElementById('opacitySlider')
};

/* ════════════════════════════════════════════════
   ЛОГИКА ИНТЕРФЕЙСА
   ════════════════════════════════════════════════ */

// Переключение вкладок
el.tabs.forEach(btn => {
  btn.onclick = () => {
    const tab = btn.dataset.tab;
    el.tabs.forEach(b => b.classList.remove('active'));
    el.pages.forEach(p => p.classList.remove('active'));
    
    btn.classList.add('active');
    document.getElementById(`tab-${tab}`).classList.add('active');
    
    if(tab === 'analysis') runFullAnalysis();
  };
});

// Настройки
el.btnOpen.onclick = () => el.panel.classList.add('open');
el.btnClose.onclick = () => el.panel.classList.remove('open');

el.themeBtns.forEach(btn => {
  btn.onclick = () => {
    document.body.className = '';
    const theme = btn.dataset.theme;
    if(theme !== 'default') document.body.classList.add(`theme-${theme}`);
  };
});

el.fontSlider.oninput = (e) => {
  const size = e.target.value;
  document.getElementById('fontSizeDisplay').textContent = size + 'px';
  document.documentElement.style.setProperty('--base-fs', size + 'px');
};

el.opacitySlider.oninput = (e) => {
  document.documentElement.style.setProperty('--bg-panel', `rgba(15, 23, 42, ${e.target.value/100})`);
};

// Подсказки
document.addEventListener('click', (e) => {
  if(e.target.classList.contains('tip-icon') && document.getElementById('tipsToggle').checked) {
    alert(TIPS[e.target.dataset.tip]);
  }
});

/* ════════════════════════════════════════════════
   МАТЕМАТИЧЕСКИЙ ДВИЖОК (ГЕНЕРАЦИЯ)
   ════════════════════════════════════════════════ */

function getCharset() {
  let set = '';
  if(document.getElementById('upper').checked) set += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if(document.getElementById('lower').checked) set += 'abcdefghijklmnopqrstuvwxyz';
  if(document.getElementById('digits').checked) set += '0123456789';
  if(document.getElementById('special').checked) set += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  return set;
}

el.btnGen.onclick = () => {
  const len = parseInt(document.getElementById('passLen').value);
  const charset = getCharset();
  const algo = document.getElementById('algoSelect').value;
  
  if(!charset) return alert("Выберите хотя бы один набор символов!");

  let pass = '';
  if(algo === 'lcg') {
    let seed = Date.now();
    const a = 1664525, c = 1013904223, m = Math.pow(2, 32);
    for(let i=0; i<len; i++) {
      seed = (a * seed + c) % m;
      pass += charset[seed % charset.length];
    }
  } else if(algo === 'crypto') {
    const vals = new Uint32Array(len);
    window.crypto.getRandomValues(vals);
    for(let i=0; i<len; i++) {
      pass += charset[vals[i] % charset.length];
    }
  } else if(algo === 'mouse') {
    // Упрощенная логика TRNG на основе накопленного пула
    if(state.mouseEntropy.length < len) return alert("Недостаточно данных мыши! Подвигайте курсором.");
    for(let i=0; i<len; i++) {
      const idx = Math.abs(state.mouseEntropy.pop()) % charset.length;
      pass += charset[idx];
    }
  }

  state.currentPassword = pass;
  el.passOut.value = pass;
  updateStrengthUI(pass);
};

// Сбор энтропии мыши
document.onmousemove = (e) => {
  const algo = document.getElementById('algoSelect').value;
  if(algo !== 'mouse') return;
  
  document.getElementById('mousePool').style.display = 'block';
  if(state.mouseEntropy.length < 500) {
    state.mouseEntropy.push(e.screenX ^ e.screenY ^ Date.now());
    const perc = Math.floor((state.mouseEntropy.length / 500) * 100);
    document.getElementById('poolFill').style.width = perc + '%';
    document.getElementById('poolStatus').textContent = perc + '%';
  }
};

/* ════════════════════════════════════════════════
   БЛОК ГЛУБОКОГО АНАЛИЗА
   ════════════════════════════════════════════════ */

function runFullAnalysis() {
  const pass = state.currentPassword;
  if(!pass) return;

  const codes = [...pass].map(c => c.charCodeAt(0));
  const len = codes.length;

  // 1. Энтропия Шеннона
  const freq = {};
  codes.forEach(c => freq[c] = (freq[c] || 0) + 1);
  let H = 0;
  Object.values(freq).forEach(count => {
    const p = count / len;
    H -= p * Math.log2(p);
  });

  // 2. Мат. ожидание и Дисперсия
  const E = codes.reduce((a,b) => a+b, 0) / len;
  const D = codes.reduce((a,b) => a + Math.pow(b - E, 2), 0) / len;

  // Вывод в UI
  document.getElementById('resEntropy').textContent = H.toFixed(3);
  document.getElementById('resMath').textContent = E.toFixed(2);
  document.getElementById('resDisp').textContent = D.toFixed(2);

  // 3. Лог расчетов (LaTeX-style)
  document.getElementById('mathLog').innerHTML = `
    <p>Расчет энтропии: H = -Σ p(x) log₂ p(x) = <strong>${H.toFixed(4)}</strong></p>
    <p>Мат. ожидание: E(x) = (1/n) Σ xᵢ = <strong>${E.toFixed(2)}</strong></p>
    <p>Дисперсия: D(x) = E(x²) - [E(x)]² = <strong>${D.toFixed(2)}</strong></p>
  `;

  renderCharts(codes, freq);
}

function renderCharts(codes, freqMap) {
  if(state.charts.freq) state.charts.freq.destroy();
  if(state.charts.phase) state.charts.phase.destroy();

  // Гистограмма
  const ctxF = document.getElementById('freqChart').getContext('2d');
  state.charts.freq = new Chart(ctxF, {
    type: 'bar',
    data: {
      labels: Object.keys(freqMap).map(c => String.fromCharCode(c)),
      datasets: [{ label: 'Частота', data: Object.values(freqMap), backgroundColor: '#38bdf8' }]
    },
    options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
  });

  // Фазовая плоскость (x_i, x_{i+1})
  const phaseData = [];
  for(let i=0; i<codes.length-1; i++) {
    phaseData.push({ x: codes[i], y: codes[i+1] });
  }
  const ctxP = document.getElementById('phaseChart').getContext('2d');
  state.charts.phase = new Chart(ctxP, {
    type: 'scatter',
    data: { datasets: [{ label: 'Связи', data: phaseData, backgroundColor: '#10b981' }] },
    options: { plugins: { legend: { display: false } } }
  });
}

function updateStrengthUI(pass) {
  const s = Math.min(pass.length * 4, 100);
  const fill = document.getElementById('strengthFill');
  fill.style.width = s + '%';
  fill.style.background = s < 40 ? '#ef4444' : s < 75 ? '#fbbf24' : '#10b981';
  document.getElementById('strengthLabel').textContent = `БЕЗОПАСНОСТЬ: ${s < 40 ? 'НИЗКАЯ' : s < 75 ? 'СРЕДНЯЯ' : 'ВЫСОКАЯ'}`;
}

// Первичная синхронизация слайдера длины
document.getElementById('passLen').oninput = (e) => {
  document.getElementById('lenLabel').textContent = e.target.value;
};
