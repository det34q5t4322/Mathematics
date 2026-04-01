'use strict';

// 1. КОНСТАНТЫ И СПРАВКА
const HELP = {
  entropy: "Энтропия Шеннона: мера неопределенности. Чем выше значение, тем сложнее взлом перебором.",
  math: "Мат. ожидание: среднее арифметическое кодов символов. Показывает центр распределения.",
  disp: "Дисперсия: мера разброса значений. Высокое значение указывает на хорошую хаотичность."
};

const state = {
  password: '',
  mouseEntropy: [],
  charts: { freq: null, phase: null }
};

// 2. ИНИЦИАЛИЗАЦИЯ ИНТЕРФЕЙСА
const el = {
  tabs: document.querySelectorAll('.tab-btn'),
  pages: document.querySelectorAll('.tab-page'),
  panel: document.getElementById('settingsPanel'),
  btnOpen: document.getElementById('openSettings'),
  btnClose: document.getElementById('closeSettings'),
  theme: document.getElementById('themeSelect'),
  font: document.getElementById('fontSlider'),
  opacity: document.getElementById('opacitySlider'),
  passOut: document.getElementById('passOutput'),
  btnGen: document.getElementById('btnGenerate')
};

// Переключение вкладок
el.tabs.forEach(btn => {
  btn.onclick = () => {
    el.tabs.forEach(b => b.classList.remove('active'));
    el.pages.forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    const target = btn.dataset.tab;
    document.getElementById(`tab-${target}`).classList.add('active');
    
    if(target === 'analysis') runAnalysis();
  };
});

// Управление настройками
el.btnOpen.onclick = () => el.panel.classList.add('open');
el.btnClose.onclick = () => el.panel.classList.remove('open');

el.theme.onchange = (e) => {
  document.body.className = e.target.value === 'default' ? '' : `theme-${e.target.value}`;
};

el.font.oninput = (e) => {
  document.getElementById('fsVal').textContent = e.target.value + 'px';
  document.documentElement.style.setProperty('--fs', e.target.value + 'px');
};

el.opacity.oninput = (e) => {
  document.documentElement.style.setProperty('--panel', `rgba(15, 23, 42, ${e.target.value/100})`);
};

document.addEventListener('click', (e) => {
  if(e.target.classList.contains('tip') && document.getElementById('tipsToggle').checked) {
    alert(HELP[e.target.dataset.tip]);
  }
});

// 3. ГЕНЕРАЦИЯ ПАРОЛЯ
function getCharset() {
  let s = '';
  if(document.getElementById('upper').checked) s += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if(document.getElementById('lower').checked) s += 'abcdefghijklmnopqrstuvwxyz';
  if(document.getElementById('digits').checked) s += '0123456789';
  if(document.getElementById('special').checked) s += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  return s;
}

el.btnGen.onclick = () => {
  const len = parseInt(document.getElementById('passLen').value);
  const charset = getCharset();
  const algo = document.getElementById('algoSelect').value;
  
  if(!charset) return alert("Выберите наборы символов!");

  let res = '';
  if(algo === 'lcg') {
    let seed = Date.now();
    for(let i=0; i<len; i++) {
      seed = (1664525 * seed + 1013904223) % 4294967296;
      res += charset[seed % charset.length];
    }
  } else if(algo === 'crypto') {
    const array = new Uint32Array(len);
    crypto.getRandomValues(array);
    for(let i=0; i<len; i++) res += charset[array[i] % charset.length];
  } else if(algo === 'mouse') {
    if(state.mouseEntropy.length < len) return alert("Недостаточно данных мыши! Подвигайте курсором.");
    for(let i=0; i<len; i++) {
      res += charset[Math.abs(state.mouseEntropy.pop()) % charset.length];
    }
  }

  state.password = res;
  el.passOut.value = res;
  updateStrength(res);
};

// Мышиный TRNG
document.onmousemove = (e) => {
  if(document.getElementById('algoSelect').value !== 'mouse') return;
  document.getElementById('mousePool').style.display = 'block';
  if(state.mouseEntropy.length < 1000) {
    state.mouseEntropy.push(e.pageX ^ e.pageY ^ Date.now());
    const p = Math.floor((state.mouseEntropy.length / 1000) * 100);
    document.getElementById('poolFill').style.width = p + '%';
    document.getElementById('poolStatus').textContent = p + '%';
  }
};

// 4. АНАЛИЗ (ВКЛАДКА 2)
function runAnalysis() {
  const pass = state.password;
  if(!pass) return;

  const codes = [...pass].map(c => c.charCodeAt(0));
  const n = codes.length;

  // Частоты
  const freq = {};
  codes.forEach(c => freq[c] = (freq[c] || 0) + 1);

  // Энтропия Шеннона
  let entropy = 0;
  Object.values(freq).forEach(count => {
    const p = count / n;
    entropy -= p * Math.log2(p);
  });

  // Мат. ожидание и Дисперсия
  const mean = codes.reduce((a, b) => a + b, 0) / n;
  const disp = codes.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / n;

  document.getElementById('valEntropy').textContent = entropy.toFixed(3);
  document.getElementById('valMath').textContent = mean.toFixed(2);
  document.getElementById('valDisp').textContent = disp.toFixed(2);

  document.getElementById('mathLog').innerHTML = `
    <p>Анализ строки длиной ${n} симв.</p>
    <p>H = -Σ pᵢ log₂ pᵢ = <b>${entropy.toFixed(5)}</b></p>
    <p>D = E[X²] - (E[X])² = <b>${disp.toFixed(2)}</b></p>
  `;

  renderCharts(freq, codes);
}

function renderCharts(freq, codes) {
  if(state.charts.freq) state.charts.freq.destroy();
  if(state.charts.phase) state.charts.phase.destroy();

  const ctxF = document.getElementById('freqChart');
  state.charts.freq = new Chart(ctxF, {
    type: 'bar',
    data: {
      labels: Object.keys(freq).map(c => String.fromCharCode(c)),
      datasets: [{ label: 'Частота', data: Object.values(freq), backgroundColor: '#38bdf8' }]
    },
    options: { responsive: true, maintainAspectRatio: false }
  });

  const ctxP = document.getElementById('phaseChart');
  const scatterData = codes.slice(0, -1).map((v, i) => ({ x: v, y: codes[i+1] }));
  state.charts.phase = new Chart(ctxP, {
    type: 'scatter',
    data: { datasets: [{ label: 'Связи x(i)/x(i+1)', data: scatterData, backgroundColor: '#10b981' }] },
    options: { responsive: true, maintainAspectRatio: false }
  });
}

function updateStrength(p) {
  const s = Math.min(p.length * 4, 100);
  const f = document.getElementById('strengthFill');
  f.style.width = s + '%';
  f.style.background = s < 40 ? '#ef4444' : s < 75 ? '#fbbf24' : '#10b981';
  document.getElementById('strengthLabel').textContent = `Надежность: ${s}%`;
}

// Синхронизация слайдера длины
document.getElementById('passLen').oninput = (e) => {
  document.getElementById('lenDisplay').textContent = e.target.value;
};
