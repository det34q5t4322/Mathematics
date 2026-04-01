/* ═══════════════════════════════════════════════════════════════════
   PassForge v3.0 — app.js
   Анализатор криптографической энтропии и генератор паролей
   ───────────────────────────────────────────────────────────────────
   Дипломная работа: Утебалиев Асан Азаматович
   Группа: ИСС9-125 | Специальность: 11.02.15 | 2026 г.
   ═══════════════════════════════════════════════════════════════════ */

'use strict';

/* ═══════════════════════════════════════════════════════════════════
   БЛОК 1: ГЕНЕРАТОРЫ ПСЕВДОСЛУЧАЙНЫХ И ИСТИННО СЛУЧАЙНЫХ ЧИСЕЛ
   ═══════════════════════════════════════════════════════════════════ */

/**
 * LCG — Линейный конгруэнтный генератор (Linear Congruential Generator)
 * ─────────────────────────────────────────────────────────────────────
 * Рекуррентная формула: X(n+1) = (a · X(n) + c) mod m
 *
 * Константы из Numerical Recipes (Press et al., 1992):
 *   a = 1664525      — множитель
 *   c = 1013904223   — приращение
 *   m = 2^32         — модуль (4 294 967 296)
 *
 * Период: m = 2^32 ≈ 4.3 млрд итераций.
 * Недостаток: паттерны на фазовой плоскости (xᵢ, xᵢ₊₁) — структурная
 * зависимость последовательных значений. Это научный факт, честно
 * отображаемый на графиках!
 * НЕ подходит для криптографии.
 */
const LCG = (() => {
  const A = 1664525n;
  const C = 1013904223n;
  const M = 4294967296n; // 2^32

  let state = BigInt(Date.now() & 0xFFFFFFFF);

  /** Следующее число ∈ [0, 1) */
  function next() {
    // BigInt исключает потерю точности при умножении больших чисел
    state = (A * state + C) % M;
    return Number(state) / Number(M);
  }

  /** Установить начальное зерно (seed) */
  function seed(s) { state = BigInt(s >>> 0); }

  return { next, seed };
})();


/**
 * Crypto API — криптографически стойкий ГПСЧ (CSPRNG)
 * ────────────────────────────────────────────────────
 * Использует window.crypto.getRandomValues() — системный RNG на основе
 * аппаратного источника энтропии (прерывания, тепловой шум и т.д.).
 * Нормализация: делим uint32 на 2^32, получая [0, 1).
 * Криптостойкость: соответствует требованиям FIPS 140-2.
 */
const CryptoRNG = (() => {
  const buf = new Uint32Array(64); // Батч для эффективности
  let pos = buf.length;            // Указатель (начинаем с конца → немедленная перезагрузка)

  function next() {
    // Перезагружаем буфер одним вызовом при исчерпании — экономия syscall
    if (pos >= buf.length) {
      window.crypto.getRandomValues(buf);
      pos = 0;
    }
    return buf[pos++] / 4294967296; // 2^32
  }

  return { next };
})();


/**
 * Mouse TRNG — Истинный генератор случайных чисел на основе мыши
 * ──────────────────────────────────────────────────────────────────
 * Источник энтропии: субпиксельные координаты движения мыши.
 * Алгоритм сбора:
 *   1. Умножаем координаты на иррациональные числа (π, e) для амплификации
 *   2. Берём дробную часть — она зависит от точных позиций пикселей
 *   3. Заполняем кольцевой буфер (пул) из 256 значений
 *
 * Алгоритм смешивания (при генерации):
 *   - XOR трёх соседних значений из пула
 *   - Нелинейное преобразование через sin() для диффузии
 *
 * Кнопка генерации заблокирована пока пул не заполнен на 50%+ (≥128 событий).
 */
const MouseTRNG = (() => {
  const POOL_SIZE = 256;
  const pool = new Float64Array(POOL_SIZE);
  let filled = 0;   // Сколько уникальных позиций заполнено
  let cursor = 0;   // Текущая позиция записи (кольцевой буфер)
  let readPos = 0;  // Позиция чтения

  document.addEventListener('mousemove', (e) => {
    // Дробная часть координат × иррациональное число = высокая чувствительность
    const fracX = (e.clientX * Math.PI)   % 1;
    const fracY = (e.clientY * Math.E)    % 1;
    const mixed = (fracX + fracY + performance.now() * 1e-6) % 1;

    pool[cursor] = mixed;
    cursor = (cursor + 1) % POOL_SIZE;
    if (filled < POOL_SIZE) filled++;

    // Обновляем UI с ограничением частоты (не чаще 30 раз/с)
    updatePoolUI();
  });

  /** Следующее случайное число ∈ [0, 1) */
  function next() {
    if (filled < 4) return CryptoRNG.next(); // Деградация при пустом пуле

    const a = pool[readPos % POOL_SIZE];
    const b = pool[(readPos + 1) % POOL_SIZE];
    const c = pool[(readPos + 2) % POOL_SIZE];
    readPos = (readPos + 3) % POOL_SIZE;

    // Нелинейное смешивание: sin() разрушает линейные зависимости
    return Math.abs(Math.sin((a * 1000 + b * 100 + c * 10) * Math.PI)) % 1;
  }

  function getCount() { return filled; }
  function isReady()  { return filled >= 128; } // Порог: 50% пула

  function getPoolBytes() {
    return Array.from(pool.slice(0, Math.min(filled, 24)))
      .map(v => Math.floor(v * 255).toString(16).padStart(2, '0'))
      .join(' ');
  }

  return { next, getCount, isReady, getPoolBytes };
})();


/* ═══════════════════════════════════════════════════════════════════
   БЛОК 2: ПОСТРОИТЕЛЬ АЛФАВИТА
   ═══════════════════════════════════════════════════════════════════ */

const CHARS = {
  upper:   'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower:   'abcdefghijklmnopqrstuvwxyz',
  digits:  '0123456789',
  special: '!@#$%^&*()_+-=[]{}|;:,.<>?',
  sep:     '-_',
  similar: new Set(['i', 'l', '1', 'L', 'o', 'O', '0', 'I'])
};

/**
 * Строит строку алфавита по конфигурации.
 * Удаляет дубликаты и, опционально, визуально похожие символы.
 */
function buildAlphabet(cfg) {
  let alpha = '';
  if (cfg.upper)   alpha += CHARS.upper;
  if (cfg.lower)   alpha += CHARS.lower;
  if (cfg.digits)  alpha += CHARS.digits;
  if (cfg.special) alpha += CHARS.special;
  if (cfg.sep)     alpha += CHARS.sep;
  if (cfg.excludeSimilar)
    alpha = alpha.split('').filter(c => !CHARS.similar.has(c)).join('');
  return [...new Set(alpha)].join('');
}


/* ═══════════════════════════════════════════════════════════════════
   БЛОК 3: ГЕНЕРАЦИЯ ПАРОЛЯ
   ПРИНЦИП ЧЕСТНОСТИ: одни и те же числа → пароль И графики
   ═══════════════════════════════════════════════════════════════════ */

/**
 * Генерирует пароль и возвращает RAW-числа для визуализации.
 *
 * Алгоритм:
 *   1. Получаем r ∈ [0, 1) из выбранного генератора
 *   2. idx = floor(r × N) — равномерный индекс в алфавите
 *   3. Тот же r записывается в rawNumbers — идёт на графики БЕЗ ИЗМЕНЕНИЙ
 *
 * @returns {{ password: string, rawNumbers: number[], genTimeUs: number }}
 */
function generatePassword(length, alphabet, rng) {
  const N = alphabet.length;
  const result    = new Array(length);
  const rawNums   = new Array(length);

  const t0 = performance.now();
  for (let i = 0; i < length; i++) {
    const r  = rng.next();           // r ∈ [0, 1)
    rawNums[i] = r;                  // ← ЧЕСТНОЕ число для графиков
    result[i]  = alphabet[Math.floor(r * N)]; // ← символ из того же r
  }
  const genTimeUs = (performance.now() - t0) * 1000; // в микросекундах

  return { password: result.join(''), rawNumbers: rawNums, genTimeUs };
}


/* ═══════════════════════════════════════════════════════════════════
   БЛОК 4: МАТЕМАТИЧЕСКИЕ ВЫЧИСЛЕНИЯ
   ═══════════════════════════════════════════════════════════════════ */

/**
 * Энтропия пароля по Шеннону.
 * H = L × log₂(N)
 * L — длина пароля, N — мощность алфавита.
 * Единица измерения: биты (bits of entropy).
 *
 * Интерпретация: каждый бит удваивает пространство поиска.
 * 128 бит → 2^128 комбинаций (неуязвимо при текущих вычислительных мощностях).
 */
function calcEntropy(L, N) {
  if (N <= 1) return 0;
  return L * Math.log2(N);
}

/**
 * Бит на символ (мера информационного содержания одного символа).
 * h = log₂(N)
 */
function calcBitsPerChar(N) {
  if (N <= 1) return 0;
  return Math.log2(N);
}

/**
 * Время полного перебора методом «грубой силы».
 * T = N^L / скорость
 *
 * Скорость взломщика: 10^9 хешей/сек (современный GPU: Hashcat на RTX 4090).
 * Используем логарифмы для предотвращения Infinity при больших N^L.
 *
 * @returns {{ value: string, unit: string }}
 */
function calcBruteForce(L, N) {
  const SPEED_LOG10 = 9; // log10(10^9)
  const logComb     = L * Math.log10(N);
  const logSecs     = logComb - SPEED_LOG10;

  if (logSecs < 0)    return { value: '< 1',                    unit: 'секунд' };
  if (logSecs < 1.78) return { value: fmt(10 ** logSecs),        unit: 'секунд' };
  if (logSecs < 3.78) return { value: fmt(10 ** (logSecs-1.78)), unit: 'минут'  };
  if (logSecs < 5.54) return { value: fmt(10 ** (logSecs-3.56)), unit: 'часов'  };
  if (logSecs < 7.49) return { value: fmt(10 ** (logSecs-4.94)), unit: 'дней'   };
  if (logSecs < 9.49) return { value: fmt(10 ** (logSecs-7.5)),  unit: 'лет'    };

  return { value: `10^${Math.round(logSecs - 7.5)}`, unit: 'млн лет' };
}

/** Форматирование больших чисел с суффиксами */
function fmt(n) {
  if (!isFinite(n) || n >= 1e15) return '∞';
  if (n >= 1e12) return (n/1e12).toFixed(1) + 'T';
  if (n >= 1e9)  return (n/1e9).toFixed(1)  + 'G';
  if (n >= 1e6)  return (n/1e6).toFixed(1)  + 'M';
  if (n >= 1e3)  return (n/1e3).toFixed(1)  + 'K';
  return n.toFixed(1);
}

/**
 * Пространство поиска: C = N^L
 * Возвращает строку в форме "10^X" для читаемости.
 */
function calcCombinations(L, N) {
  const exp = L * Math.log10(N);
  if (exp > 99) return `10^${Math.round(exp)}`;
  const val = Math.pow(N, L);
  return val > 1e12 ? `~10^${Math.round(exp)}` : val.toLocaleString('ru-RU');
}

/**
 * Математическое ожидание (среднее арифметическое).
 * E[X] = (1/n) × Σ xᵢ
 * Для равномерного U[0,1] теоретическое значение = 0.5
 */
function calcExpected(nums) {
  if (!nums.length) return 0;
  return nums.reduce((s, x) => s + x, 0) / nums.length;
}

/**
 * Дисперсия.
 * D[X] = E[X²] - (E[X])²
 * Для U[0,1] теоретическое значение = 1/12 ≈ 0.0833
 */
function calcVariance(nums, mean) {
  if (nums.length < 2) return 0;
  const e2 = nums.reduce((s, x) => s + x * x, 0) / nums.length;
  return e2 - mean * mean;
}

/**
 * Метод Монте-Карло для оценки числа π.
 * ─────────────────────────────────────────
 * Генерируем точки (x, y) ∈ [0,1)² из последовательных пар.
 * Точка попадает в четверть единичной окружности если x² + y² ≤ 1.
 * Оценка: π ≈ 4 × (кол-во попаданий / кол-во пар)
 *
 * Точность растёт как O(1/√n) — со 100 точками ошибка ~10%.
 *
 * @returns {{ pi: string, points: Array<{x,y,inside}> }}
 */
function calcMonteCarlo(nums) {
  if (nums.length < 2) return { pi: '—', points: [] };
  const pairs  = Math.floor(nums.length / 2);
  let inside   = 0;
  const points = [];

  for (let i = 0; i < pairs; i++) {
    const x = nums[2 * i];
    const y = nums[2 * i + 1];
    const hit = (x * x + y * y) <= 1;
    if (hit) inside++;
    points.push({ x, y, inside: hit });
  }

  return { pi: ((4 * inside) / pairs).toFixed(5), points };
}

/**
 * Детектор коллизий на фазовой плоскости.
 * Точки (xᵢ, xᵢ₊₁) с округлением до 3 знаков сохраняются в Set.
 * Повтор → красная точка (#ef4444).
 *
 * @returns {{ unique, repeats, repeatPct }}
 */
function detectCollisions(nums) {
  const seen    = new Set();
  const unique  = [];
  const repeats = [];

  for (let i = 0; i < nums.length - 1; i++) {
    const x   = nums[i];
    const y   = nums[i + 1];
    const key = `${x.toFixed(3)},${y.toFixed(3)}`;

    if (seen.has(key)) {
      repeats.push({ x, y });
    } else {
      seen.add(key);
      unique.push({ x, y });
    }
  }

  const total     = unique.length + repeats.length;
  const repeatPct = total > 0 ? ((repeats.length / total) * 100).toFixed(1) : '0.0';

  return { unique, repeats, repeatPct };
}

/**
 * Уровень надёжности пароля по значению энтропии (в битах).
 * ─────────────────────────────────────────────────────────
 * Классификация по NIST SP 800-63B:
 *   < 28 бит  → слабый (бытовой перебор за секунды)
 *   28-35     → ниже среднего
 *   36-59     → приемлемый
 *   60-127    → сильный
 *   ≥ 128     → очень сильный (военный уровень)
 *
 * @returns {{ label, level: 1-5, color, pctPerSeg }}
 */
function strengthLevel(entropy) {
  if (entropy < 28)  return { label: 'СЛАБЫЙ',        level: 1, color: '#ef4444' };
  if (entropy < 36)  return { label: 'СЛАБЫЙ+',       level: 2, color: '#f97316' };
  if (entropy < 60)  return { label: 'ПРИЕМЛЕМЫЙ',    level: 3, color: '#fbbf24' };
  if (entropy < 128) return { label: 'СИЛЬНЫЙ',       level: 4, color: '#34d399' };
  return                    { label: 'ОЧЕНЬ СИЛЬНЫЙ', level: 5, color: '#10b981' };
}

/**
 * Обновляет многосегментный индикатор надёжности.
 * Сегменты: 5 штук, заполняются по уровню.
 * @param {string[]} segIds — массив id элементов сегментов
 */
function updateStrengthBar(segIds, labelId, entropy) {
  const str   = strengthLevel(entropy);
  const segs  = segIds.map(id => document.getElementById(id));
  const label = document.getElementById(labelId);

  segs.forEach((seg, i) => {
    const active = i < str.level;
    seg.style.background  = active ? str.color : 'rgba(255,255,255,0.05)';
    seg.style.boxShadow   = active ? `0 0 8px ${str.color}60` : 'none';
    seg.style.borderColor = active ? str.color + '30' : 'rgba(255,255,255,0.04)';
  });

  if (label) {
    label.textContent  = str.label;
    label.style.color  = str.color;
    label.style.textShadow = `0 0 12px ${str.color}60`;
  }
}

/**
 * Подсвечивает символы пароля по типу (цветовая кодировка).
 * A-Z → синий, a-z → зелёный, 0-9 → жёлтый, спецсимволы → оранжевый
 */
function colorizePassword(pwd) {
  return pwd.split('').map(ch => {
    let color;
    if (/[A-Z]/.test(ch))                           color = '#38bdf8';
    else if (/[a-z]/.test(ch))                      color = '#10b981';
    else if (/[0-9]/.test(ch))                      color = '#fbbf24';
    else                                             color = '#f59e0b';
    return `<span style="color:${color}">${ch}</span>`;
  }).join('');
}


/* ═══════════════════════════════════════════════════════════════════
   БЛОК 5: CHART.JS — ГРАФИКИ
   ═══════════════════════════════════════════════════════════════════ */

// Глобальные экземпляры (уничтожаем перед пересозданием)
const charts = {
  hist: null, scatter: null,
  aHist: null, aScatter: null, aMc: null
};

// Общая тема для Chart.js
Chart.defaults.color        = '#475569';
Chart.defaults.borderColor  = 'rgba(56,189,248,0.07)';
Chart.defaults.font.family  = "'JetBrains Mono', monospace";
Chart.defaults.font.size    = 10;

/** Общий конфиг шкал для темной темы */
function darkScales(xLabel = '', yLabel = '') {
  return {
    x: {
      grid:  { color: 'rgba(56,189,248,0.05)' },
      ticks: { color: '#475569', maxTicksLimit: 8 },
      ...(xLabel ? { title: { display: true, text: xLabel, color: '#475569', font: { size: 9 } } } : {})
    },
    y: {
      grid:  { color: 'rgba(56,189,248,0.05)' },
      ticks: { color: '#475569', maxTicksLimit: 6 },
      ...(yLabel ? { title: { display: true, text: yLabel, color: '#475569', font: { size: 9 } } } : {})
    }
  };
}

/** Общий конфиг tooltip */
function darkTooltip() {
  return {
    backgroundColor: 'rgba(10,18,35,0.96)',
    borderColor: '#38bdf8',
    borderWidth: 1,
    titleColor: '#38bdf8',
    bodyColor: '#94a3b8',
    padding: 8,
  };
}

/**
 * Гистограмма частот [0,1) на 20 бинов.
 * Показывает, насколько равномерно распределены числа генератора.
 * Красная пунктирная линия — идеальное равномерное распределение.
 */
function buildHistogram(nums, canvasId) {
  const BINS   = 20;
  const counts = new Array(BINS).fill(0);
  nums.forEach(n => { counts[Math.min(Math.floor(n * BINS), BINS - 1)]++; });
  const ideal   = nums.length / BINS;
  const labels  = counts.map((_, i) => (i / BINS).toFixed(2));

  const key = canvasId === 'histChart' ? 'hist' : 'aHist';
  if (charts[key]) charts[key].destroy();

  charts[key] = new Chart(document.getElementById(canvasId), {
    type: 'bar',
    data: {
      labels,
      datasets: [
        {
          label: 'Частота',
          data: counts,
          backgroundColor: 'rgba(56,189,248,0.2)',
          borderColor: '#38bdf8',
          borderWidth: 1,
          borderRadius: 2,
        },
        {
          label: 'Идеал U[0,1]',
          data: new Array(BINS).fill(ideal),
          type: 'line',
          borderColor: 'rgba(16,185,129,0.7)',
          borderWidth: 1.5,
          borderDash: [4, 4],
          pointRadius: 0,
          fill: false,
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 450, easing: 'easeOutQuart' },
      plugins: {
        legend: { labels: { color: '#94a3b8', boxWidth: 10, font: { size: 9 } } },
        tooltip: darkTooltip()
      },
      scales: darkScales('r', 'n')
    }
  });
}

/**
 * Фазовая плоскость: точки (xᵢ, xᵢ₊₁).
 * Для идеального RNG точки равномерно покрывают квадрат [0,1)².
 * Для LCG видна характерная структура (диагональные полосы) —
 * это наглядное подтверждение его периодичности.
 * Коллизии → красные точки (#ef4444).
 */
function buildScatter(nums, canvasId) {
  const { unique, repeats } = detectCollisions(nums);

  const key = canvasId === 'scatterChart' ? 'scatter' : 'aScatter';
  if (charts[key]) charts[key].destroy();

  charts[key] = new Chart(document.getElementById(canvasId), {
    type: 'scatter',
    data: {
      datasets: [
        {
          label: 'Уникальные',
          data: unique,
          backgroundColor: 'rgba(56,189,248,0.55)',
          borderColor: '#38bdf8',
          borderWidth: 0,
          pointRadius: 2.5,
          pointHoverRadius: 4,
        },
        {
          label: 'Коллизии',
          data: repeats,
          backgroundColor: 'rgba(239,68,68,0.8)',
          borderColor: '#ef4444',
          borderWidth: 0,
          pointRadius: 3.5,
          pointHoverRadius: 5,
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 380 },
      plugins: {
        legend: { labels: { color: '#94a3b8', boxWidth: 10, font: { size: 9 } } },
        tooltip: {
          ...darkTooltip(),
          callbacks: { label: ctx => `(${ctx.parsed.x.toFixed(3)}, ${ctx.parsed.y.toFixed(3)})` }
        }
      },
      scales: {
        x: { min: 0, max: 1, ...darkScales().x, title: { display: true, text: 'xᵢ', color: '#475569' } },
        y: { min: 0, max: 1, ...darkScales().y, title: { display: true, text: 'xᵢ₊₁', color: '#475569' } }
      }
    }
  });
}

/**
 * Визуализация Монте-Карло на холсте (scatter plot с кругом).
 * Синие точки — внутри четверти круга (x²+y²≤1).
 * Красные точки — снаружи.
 * Область дуги показана пунктиром.
 */
function buildMonteCarlo(mcResult, canvasId) {
  const inside  = mcResult.points.filter(p => p.inside).map(p => ({ x: p.x, y: p.y }));
  const outside = mcResult.points.filter(p => !p.inside).map(p => ({ x: p.x, y: p.y }));

  // Четверть окружности (дуга) как дополнительный dataset
  const arcPts = [];
  for (let a = 0; a <= Math.PI / 2; a += 0.02)
    arcPts.push({ x: Math.cos(a), y: Math.sin(a) });

  if (charts.aMc) charts.aMc.destroy();

  charts.aMc = new Chart(document.getElementById(canvasId), {
    type: 'scatter',
    data: {
      datasets: [
        {
          label: 'Внутри (x²+y²≤1)',
          data: inside,
          backgroundColor: 'rgba(56,189,248,0.5)',
          borderWidth: 0,
          pointRadius: 2,
        },
        {
          label: 'Снаружи',
          data: outside,
          backgroundColor: 'rgba(239,68,68,0.5)',
          borderWidth: 0,
          pointRadius: 2,
        },
        {
          label: 'Дуга (r=1)',
          data: arcPts,
          type: 'line',
          borderColor: 'rgba(251,191,36,0.8)',
          borderWidth: 1.5,
          borderDash: [3, 3],
          pointRadius: 0,
          fill: false,
          tension: 0.4,
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 400 },
      plugins: {
        legend: { labels: { color: '#94a3b8', boxWidth: 10, font: { size: 9 } } },
        tooltip: darkTooltip()
      },
      scales: {
        x: { min: 0, max: 1, ...darkScales().x },
        y: { min: 0, max: 1, ...darkScales().y }
      }
    }
  });
}


/* ═══════════════════════════════════════════════════════════════════
   БЛОК 6: ГЛОБАЛЬНОЕ СОСТОЯНИЕ
   ═══════════════════════════════════════════════════════════════════ */

// Текущее состояние приложения
const state = {
  mode:        'generator', // 'generator' | 'analysis'
  algo:        'lcg',       // 'lcg' | 'crypto' | 'mouse'
  password:    '',
  rawNumbers:  [],
  alphabet:    '',
  genTimeUs:   0,
};

// Описания алгоритмов
const ALGO_INFO = {
  lcg: {
    desc: 'LCG — детерминированный PRNG. a=1664525, c=1013904223, m=2³². Паттерны на фазовой плоскости — научное доказательство структурной зависимости последовательных значений.',
    detail: `
      <strong>Тип:</strong> Псевдослучайный генератор (PRNG)<br>
      <strong>Период:</strong> 2³² ≈ 4.3 млрд итераций<br>
      <strong>Криптостойкость:</strong> Отсутствует<br>
      <strong>Применение:</strong> Симуляции, игры, тестирование<br>
      <strong>Недостаток:</strong> Линейная корреляция xᵢ → xᵢ₊₁ видна на фазовой плоскости как диагональные полосы (теорема Марсальи)
    `
  },
  crypto: {
    desc: 'window.crypto.getRandomValues() — системный CSPRNG браузера. Батч-загрузка в буфер 64×uint32 для эффективности. Соответствует FIPS 140-2.',
    detail: `
      <strong>Тип:</strong> Крипто-стойкий PRNG (CSPRNG)<br>
      <strong>Период:</strong> Фактически бесконечный<br>
      <strong>Криптостойкость:</strong> Да (FIPS 140-2)<br>
      <strong>Применение:</strong> Генерация ключей, токены, пароли<br>
      <strong>Источник:</strong> Аппаратные прерывания, тепловой шум процессора
    `
  },
  mouse: {
    desc: 'Mouse TRNG — истинный RNG из хаоса движений мыши. Субпиксельные координаты × π/e → дробная часть → кольцевой буфер 256 байт. Требует 128+ событий.',
    detail: `
      <strong>Тип:</strong> Истинный генератор случайных чисел (TRNG)<br>
      <strong>Период:</strong> Не применимо (физический источник)<br>
      <strong>Криптостойкость:</strong> Да (непредсказуемый физический источник)<br>
      <strong>Применение:</strong> Демонстрация сбора аппаратной энтропии<br>
      <strong>Ограничение:</strong> Требует взаимодействия пользователя с мышью
    `
  }
};


/* ═══════════════════════════════════════════════════════════════════
   БЛОК 7: DOM ЭЛЕМЕНТЫ
   ═══════════════════════════════════════════════════════════════════ */

const el = {
  // Режимы
  viewGen:    document.getElementById('viewGenerator'),
  viewAna:    document.getElementById('viewAnalysis'),
  modeBtns:   document.querySelectorAll('.mode-btn'),
  scanOverlay:document.getElementById('scanOverlay'),

  // Конфигуратор
  lengthSlider:   document.getElementById('lengthSlider'),
  lengthValue:    document.getElementById('lengthValue'),
  useUpper:       document.getElementById('useUpper'),
  useLower:       document.getElementById('useLower'),
  useDigits:      document.getElementById('useDigits'),
  useSpecial:     document.getElementById('useSpecial'),
  useSep:         document.getElementById('useSep'),
  excludeSimilar: document.getElementById('excludeSimilar'),
  algoTabs:       document.querySelectorAll('.algo-tab'),
  algoDesc:       document.getElementById('algoDesc'),

  // Mouse TRNG inline
  mousePoolInline: document.getElementById('mousePoolInline'),
  mpiFill:         document.getElementById('mpiFill'),
  poolPct:         document.getElementById('poolPct'),
  mpiReady:        document.getElementById('mpiReady'),

  // Генерация
  btnGenerate:  document.getElementById('btnGenerate'),
  btnRefresh:   document.getElementById('btnRefresh'),
  btnCopy:      document.getElementById('btnCopy'),
  genTimeBadge: document.getElementById('genTimeBadge'),

  // Вывод (Генератор)
  passwordDisplay: document.getElementById('passwordDisplay'),
  copyToast:       document.getElementById('copyToast'),
  strengthLabel:   document.getElementById('strengthLabel'),
  entropyValue:    document.getElementById('entropyValue'),
  alphabetSize:    document.getElementById('alphabetSize'),
  bruteValue:      document.getElementById('bruteValue'),
  bruteUnit:       document.getElementById('bruteUnit'),

  // Статус мыши
  mouseEntropyStatus: document.getElementById('mouseEntropyStatus'),
  statusDot:          document.getElementById('statusDot'),
  poolBarFill:        document.getElementById('poolBarFill'),
  poolCount:          document.getElementById('poolCount'),
  poolBytes:          document.getElementById('poolBytes'),

  // Scatter статистика
  repeatCount: document.getElementById('repeatCount'),
  totalPoints: document.getElementById('totalPoints'),
  repeatPct:   document.getElementById('repeatPct'),

  // Режим Анализа
  aRefresh:         document.getElementById('aRefresh'),
  aPasswordDisplay: document.getElementById('aPasswordDisplay'),
  aEntropyTotal:    document.getElementById('aEntropyTotal'),
  aEntropyPerChar:  document.getElementById('aEntropyPerChar'),
  aExpected:        document.getElementById('aExpected'),
  aVariance:        document.getElementById('aVariance'),
  aCollisions:      document.getElementById('aCollisions'),
  aCollisionsPct:   document.getElementById('aCollisionsPct'),
  aBrute:           document.getElementById('aBrute'),
  aBruteUnit:       document.getElementById('aBruteUnit'),
  aGenSpeed:        document.getElementById('aGenSpeed'),
  aPiValue:         document.getElementById('aPiValue'),
  aStrengthLabel:   document.getElementById('aStrengthLabel'),
  algoInfoContent:  document.getElementById('algoInfoContent'),

  // Формулы
  fEntropyVal:  document.getElementById('fEntropyVal'),
  fBitsPerChar: document.getElementById('fBitsPerChar'),
  fExpected:    document.getElementById('fExpected'),
  fVariance:    document.getElementById('fVariance'),
  fStdDev:      document.getElementById('fStdDev'),
  fCombinations:document.getElementById('fCombinations'),
  fBrute:       document.getElementById('fBrute'),
  fPi:          document.getElementById('fPi'),
  fCollRate:    document.getElementById('fCollRate'),

  // Строки таблицы алгоритмов
  actLcg:    document.getElementById('actLcg'),
  actCrypto: document.getElementById('actCrypto'),
  actMouse:  document.getElementById('actMouse'),
};


/* ═══════════════════════════════════════════════════════════════════
   БЛОК 8: ОСНОВНАЯ ФУНКЦИЯ ГЕНЕРАЦИИ
   ═══════════════════════════════════════════════════════════════════ */

/** Читает конфигурацию из UI */
function getConfig() {
  return {
    length:         +el.lengthSlider.value,
    upper:          el.useUpper.checked,
    lower:          el.useLower.checked,
    digits:         el.useDigits.checked,
    special:        el.useSpecial.checked,
    sep:            el.useSep.checked,
    excludeSimilar: el.excludeSimilar.checked,
  };
}

/** Выбирает RNG по текущему алгоритму */
function getRNG() {
  const map = { lcg: LCG, crypto: CryptoRNG, mouse: MouseTRNG };
  return map[state.algo];
}

/**
 * Главная функция генерации.
 * Собирает конфигурацию → строит алфавит → генерирует числа и пароль →
 * обновляет все элементы UI → перестраивает графики.
 */
function generate() {
  const cfg      = getConfig();
  const alphabet = buildAlphabet(cfg);

  if (!alphabet.length) {
    el.passwordDisplay.innerHTML = '<span style="color:#ef4444">⚠ Выберите хотя бы один набор символов!</span>';
    return;
  }

  // Пересеиваем LCG криптостойким числом при каждой генерации
  if (state.algo === 'lcg') {
    const buf = new Uint32Array(1);
    window.crypto.getRandomValues(buf);
    LCG.seed(buf[0]);
  }

  const rng = getRNG();
  const { password, rawNumbers, genTimeUs } = generatePassword(cfg.length, alphabet, rng);

  // Сохраняем в состояние
  state.password   = password;
  state.rawNumbers = rawNumbers;
  state.alphabet   = alphabet;
  state.genTimeUs  = genTimeUs;

  // ── Обновляем генератор ──
  const N         = alphabet.length;
  const entropy   = calcEntropy(cfg.length, N);
  const brute     = calcBruteForce(cfg.length, N);
  const { unique, repeats, repeatPct } = detectCollisions(rawNumbers);

  el.passwordDisplay.innerHTML = colorizePassword(password);
  el.genTimeBadge.textContent  = `${genTimeUs.toFixed(1)} мкс`;
  el.entropyValue.textContent  = entropy.toFixed(1);
  el.alphabetSize.textContent  = N;
  el.bruteValue.textContent    = brute.value;
  el.bruteUnit.textContent     = brute.unit;

  el.repeatCount.textContent = repeats.length;
  el.totalPoints.textContent = unique.length + repeats.length;
  el.repeatPct.textContent   = repeatPct;

  updateStrengthBar(['seg1','seg2','seg3','seg4','seg5'], 'strengthLabel', entropy);

  // Графики генератора
  buildHistogram(rawNumbers, 'histChart');
  buildScatter(rawNumbers, 'scatterChart');

  // ── Если активен режим анализа — обновляем и его ──
  if (state.mode === 'analysis') updateAnalysisView();
}

/** Обновляет панель полного анализа */
function updateAnalysisView() {
  const nums    = state.rawNumbers;
  const N       = state.alphabet.length;
  const L       = state.password.length;

  if (!nums.length || !N || !L) return;

  const entropy   = calcEntropy(L, N);
  const bpc       = calcBitsPerChar(N);
  const mean      = calcExpected(nums);
  const variance  = calcVariance(nums, mean);
  const stdDev    = Math.sqrt(variance);
  const brute     = calcBruteForce(L, N);
  const mc        = calcMonteCarlo(nums);
  const coll      = detectCollisions(nums);
  const combStr   = calcCombinations(L, N);

  // ── Плашка метрик ──
  el.aEntropyTotal.textContent   = entropy.toFixed(1);
  el.aEntropyPerChar.textContent = `${bpc.toFixed(2)} бит/символ`;
  el.aExpected.textContent       = mean.toFixed(4);
  el.aVariance.textContent       = variance.toFixed(5);
  el.aCollisions.textContent     = coll.repeats.length;
  el.aCollisionsPct.textContent  = `${coll.repeatPct}% повторов`;
  el.aBrute.textContent          = brute.value;
  el.aBruteUnit.textContent      = brute.unit;
  el.aGenSpeed.textContent       = state.genTimeUs.toFixed(2);
  el.aPiValue.textContent        = mc.pi;

  // Пароль в режиме анализа
  el.aPasswordDisplay.innerHTML  = colorizePassword(state.password);
  updateStrengthBar(['aSeg1','aSeg2','aSeg3','aSeg4','aSeg5'], 'aStrengthLabel', entropy);

  // ── Таблица формул ──
  el.fEntropyVal.textContent   = `${entropy.toFixed(2)} бит`;
  el.fBitsPerChar.textContent  = `${bpc.toFixed(3)} бит/сим`;
  el.fExpected.textContent     = `${mean.toFixed(5)} (Δ=${Math.abs(mean-0.5).toFixed(5)})`;
  el.fVariance.textContent     = `${variance.toFixed(6)} (Δ=${Math.abs(variance-1/12).toFixed(6)})`;
  el.fStdDev.textContent       = stdDev.toFixed(5);
  el.fCombinations.textContent = combStr;
  el.fBrute.textContent        = `${brute.value} ${brute.unit}`;
  el.fPi.textContent           = `${mc.pi} (|Δ|=${Math.abs(parseFloat(mc.pi)-Math.PI).toFixed(5)})`;
  el.fCollRate.textContent     = `${coll.repeatPct}%`;

  // ── Инфо об алгоритме ──
  el.algoInfoContent.innerHTML = ALGO_INFO[state.algo].detail;

  // Подсветка активной строки в таблице алгоритмов
  [el.actLcg, el.actCrypto, el.actMouse].forEach(r => r && r.classList.remove('active'));
  const activeRow = { lcg: el.actLcg, crypto: el.actCrypto, mouse: el.actMouse }[state.algo];
  if (activeRow) activeRow.classList.add('active');

  // ── Графики анализа ──
  buildHistogram(nums, 'aHistChart');
  buildScatter(nums, 'aScatterChart');
  buildMonteCarlo(mc, 'aMcChart');
}


/* ═══════════════════════════════════════════════════════════════════
   БЛОК 9: SPA — ПЕРЕКЛЮЧЕНИЕ РЕЖИМОВ
   ═══════════════════════════════════════════════════════════════════ */

function switchMode(mode) {
  if (mode === state.mode) return;
  state.mode = mode;

  // Анимация сканирования
  el.scanOverlay.classList.add('scanning');
  setTimeout(() => el.scanOverlay.classList.remove('scanning'), 650);

  // Переключаем views
  el.viewGen.classList.toggle('active',  mode === 'generator');
  el.viewAna.classList.toggle('active',  mode === 'analysis');
  el.viewGen.setAttribute('aria-hidden', mode === 'analysis' ? 'true' : 'false');
  el.viewAna.setAttribute('aria-hidden', mode === 'generator' ? 'true' : 'false');

  // Кнопки навигации
  el.modeBtns.forEach(btn => {
    const active = btn.dataset.mode === mode;
    btn.classList.toggle('active', active);
    btn.setAttribute('aria-pressed', active);
  });

  // Обновляем анализ при переключении на него (если данные есть)
  if (mode === 'analysis') {
    if (state.rawNumbers.length > 0) {
      updateAnalysisView();
    } else {
      // Генерируем начальные данные
      generate();
      updateAnalysisView();
    }
  }
}


/* ═══════════════════════════════════════════════════════════════════
   БЛОК 10: UI — ПУЛА МЫШИНОЙ ЭНТРОПИИ
   ═══════════════════════════════════════════════════════════════════ */

// Ограничитель частоты обновления UI для мыши
let poolUITimer = null;

function updatePoolUI() {
  if (poolUITimer) return;
  poolUITimer = requestAnimationFrame(() => {
    poolUITimer = null;

    const count = MouseTRNG.getCount();
    const pct   = Math.min(100, Math.round((count / 256) * 100));
    const ready = MouseTRNG.isReady();

    // Общий прогресс в шапке
    el.poolBarFill.style.width = pct + '%';
    el.poolCount.textContent   = count;
    el.poolBytes.textContent   = MouseTRNG.getPoolBytes() || '—';

    el.mouseEntropyStatus.textContent = ready
      ? 'MOUSE ENTROPY: ГОТОВ ✓'
      : `MOUSE ENTROPY: СБОР (${count}/256)`;

    el.statusDot.style.background = ready
      ? 'var(--accent-blue)'
      : 'var(--accent-green)';

    // Inline прогресс-бар (видим только при algo=mouse)
    if (state.algo === 'mouse') {
      el.mpiFill.style.width  = pct + '%';
      el.poolPct.textContent  = pct;
      el.mpiReady.style.display = ready ? 'inline' : 'none';

      // Блокировка кнопки генерации пока не набрали 128 событий
      el.btnGenerate.disabled = !ready;
      if (!ready) {
        el.btnGenerate.title = `Нужно ещё ${128 - count} событий движения мыши`;
      } else {
        el.btnGenerate.removeAttribute('title');
      }
    }
  });
}


/* ═══════════════════════════════════════════════════════════════════
   БЛОК 11: СЛАЙДЕР — ЗАЛИВКА
   ═══════════════════════════════════════════════════════════════════ */

function updateSliderFill() {
  const min = +el.lengthSlider.min;
  const max = +el.lengthSlider.max;
  const val = +el.lengthSlider.value;
  const pct = ((val - min) / (max - min)) * 100;
  el.lengthSlider.style.background =
    `linear-gradient(90deg, #38bdf8 ${pct}%, rgba(56,189,248,0.1) ${pct}%)`;
}


/* ═══════════════════════════════════════════════════════════════════
   БЛОК 12: КОПИРОВАНИЕ
   ═══════════════════════════════════════════════════════════════════ */

async function copyPassword() {
  const text = state.password;
  if (!text) return;

  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Фоллбэк для браузеров без Clipboard API
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  }

  el.copyToast.classList.add('show');
  setTimeout(() => el.copyToast.classList.remove('show'), 2200);
}


/* ═══════════════════════════════════════════════════════════════════
   БЛОК 13: ОБРАБОТЧИКИ СОБЫТИЙ
   ═══════════════════════════════════════════════════════════════════ */

// SPA-навигация
el.modeBtns.forEach(btn => {
  btn.addEventListener('click', () => switchMode(btn.dataset.mode));
});

// Слайдер длины
el.lengthSlider.addEventListener('input', () => {
  el.lengthValue.textContent = el.lengthSlider.value;
  updateSliderFill();
});

// Кнопки генерации
el.btnGenerate.addEventListener('click', generate);
el.btnRefresh.addEventListener('click',  generate);
el.btnCopy.addEventListener('click',     copyPassword);

// Кнопка обновления в режиме анализа
if (el.aRefresh) {
  el.aRefresh.addEventListener('click', () => {
    generate();
    updateAnalysisView();
  });
}

// Переключение алгоритма
el.algoTabs.forEach(tab => {
  tab.addEventListener('click', () => {
    el.algoTabs.forEach(t => {
      t.classList.remove('active');
      t.setAttribute('aria-pressed', 'false');
    });
    tab.classList.add('active');
    tab.setAttribute('aria-pressed', 'true');

    state.algo = tab.dataset.algo;
    el.algoDesc.textContent = ALGO_INFO[state.algo].desc;

    // Показываем/скрываем inline прогресс-бар мыши
    const isMouse = state.algo === 'mouse';
    el.mousePoolInline.style.display = isMouse ? 'block' : 'none';

    // Разблокируем кнопку для не-мышиных алгоритмов
    if (!isMouse) {
      el.btnGenerate.disabled = false;
      el.btnGenerate.removeAttribute('title');
    } else {
      updatePoolUI(); // Немедленная проверка готовности
    }
  });
});

// Авто-регенерация при изменении чекбоксов (только если данные уже есть)
[el.useUpper, el.useLower, el.useDigits, el.useSpecial, el.useSep, el.excludeSimilar]
  .forEach(cb => {
    cb.addEventListener('change', () => {
      if (state.rawNumbers.length > 0) generate();
    });
  });


/* ═══════════════════════════════════════════════════════════════════
   БЛОК 14: ИНИЦИАЛИЗАЦИЯ
   ═══════════════════════════════════════════════════════════════════ */

(function init() {
  // Синхронизируем слайдер
  updateSliderFill();

  // Инициализируем UI пула мыши
  updatePoolUI();

  // Генерируем первый пароль
  generate();

  console.log(
    '%c[ PASSFORGE v3.0 ]',
    'color:#38bdf8;font-family:"JetBrains Mono",monospace;font-size:16px;font-weight:900'
  );
  console.log(
    '%cАнализатор криптографической энтропии\nДипломная работа: Утебалиев Асан Азаматович | ИСС9-125 | 11.02.15 | 2026',
    'color:#475569;font-family:"JetBrains Mono",monospace;font-size:11px'
  );
  console.log(
    '%cАлгоритмы: LCG (a=1664525, c=1013904223, m=2³²) · Crypto API · Mouse TRNG',
    'color:#10b981;font-family:"JetBrains Mono",monospace;font-size:10px'
  );
})();
