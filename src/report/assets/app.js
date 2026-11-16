(function () {
  'use strict';

  var THEME_KEY = 'sarf-report-theme';
  var DASH = '\u2014';
  var TREE_CAP = 400;
  var WINDOW_LOG_CAP = 25;
  var WINDOW_EVENT_CAP = 20;
  var WINDOW_CAP = 200;
  var TOP_CAP = 100;
  var LOG_CAP = 500;
  var EVENT_CAP = 300;
  var INCIDENT_CAP = 500;
  var COLLECTOR_CAP = 200;
  var GAP_CAP = 300;
  var INTEGRATION_CAP = 200;
  var CHART_POINT_CAP = 4000;
  var MONO = 'ui-monospace, "SFMono-Regular", "Cascadia Code", "Cascadia Mono", Consolas, "Liberation Mono", Menlo, monospace';

  var METRIC_LABELS = {
    cpu: 'CPU utilization',
    cpu_pct: 'CPU utilization',
    host_cpu_pct: 'CPU utilization',
    mem_pct: 'Memory utilization',
    memory_pct: 'Memory utilization',
    memory: 'Memory usage',
    psi_cpu: 'CPU pressure',
    psi_memory: 'Memory pressure',
    psi_io: 'I/O pressure',
    load: 'Load average (1m)',
    load1: 'Load average (1m)',
    io_read: 'Disk read bytes',
    io_write: 'Disk write bytes',
    net_rx: 'Network receive bytes',
    net_tx: 'Network transmit bytes',
    net_rx_bps: 'Network receive rate',
    net_tx_bps: 'Network transmit rate',
    disk_read_bps: 'Disk read rate',
    disk_write_bps: 'Disk write rate'
  };

  var VIEW_ALIASES = {
    summary: 'summary',
    overview: 'summary',
    windows: 'windows',
    'what-happened': 'windows',
    timeline: 'timeline',
    trace: 'timeline',
    top: 'top',
    contributors: 'top',
    processes: 'processes',
    tree: 'processes',
    incidents: 'incidents',
    logs: 'logs',
    'logs-events': 'logs',
    coverage: 'coverage',
    gaps: 'coverage'
  };

  var SERIES = {
    cpu_pct: { label: 'CPU %', color: '--series-cpu', format: 'pct', axis: 'left' },
    load1: { label: 'Load 1m', color: '--series-load', format: 'number', axis: 'right' },
    mem_pct: { label: 'Memory %', color: '--series-mem', format: 'pct', axis: 'left' },
    mem_used_bytes: { label: 'Used bytes', color: '--series-memb', format: 'bytes', axis: 'right' },
    psi_cpu: { label: 'CPU pressure', color: '--series-psicpu', format: 'pct', axis: 'left' },
    psi_memory: { label: 'Memory pressure', color: '--series-psimem', format: 'pct', axis: 'left' },
    psi_io: { label: 'I/O pressure', color: '--series-psiio', format: 'pct', axis: 'left' },
    net_rx_bps: { label: 'Network RX', color: '--series-rx', format: 'rate', axis: 'left' },
    net_tx_bps: { label: 'Network TX', color: '--series-tx', format: 'rate', axis: 'left' },
    disk_read_bps: { label: 'Disk read', color: '--series-read', format: 'rate', axis: 'left' },
    disk_write_bps: { label: 'Disk write', color: '--series-write', format: 'rate', axis: 'left' }
  };

  var CHART_SPECS = [
    {
      id: 'cpu',
      title: 'Host CPU & load',
      note: 'CPU is percent of one logical core; load is the 1-minute run-queue average. Missing samples are gaps.',
      wide: true,
      keys: ['cpu_pct', 'load1'],
      leftFormat: 'pct',
      rightFormat: 'number'
    },
    {
      id: 'memory',
      title: 'Memory',
      note: 'Utilization on the left, used bytes on the right (IEC). Missing samples are gaps.',
      keys: ['mem_pct', 'mem_used_bytes'],
      leftFormat: 'pct',
      rightFormat: 'bytes'
    },
    {
      id: 'pressure',
      title: 'Pressure (PSI)',
      note: 'CPU, memory and I/O pressure as percentages of one logical core. Missing samples are gaps.',
      keys: ['psi_cpu', 'psi_memory', 'psi_io'],
      leftFormat: 'pct',
      rightFormat: null
    },
    {
      id: 'network',
      title: 'Network throughput',
      note: 'Receive and transmit bytes per second. Missing samples are gaps.',
      keys: ['net_rx_bps', 'net_tx_bps'],
      leftFormat: 'rate',
      rightFormat: null
    },
    {
      id: 'disk',
      title: 'Disk throughput',
      note: 'Read and write bytes per second. Missing samples are gaps.',
      keys: ['disk_read_bps', 'disk_write_bps'],
      leftFormat: 'rate',
      rightFormat: null
    }
  ];

  var state = {
    data: null,
    meta: {},
    summary: {},
    view: 'summary',
    theme: 'dark',
    tz: null,
    tabs: [],
    charts: [],
    chartObserver: null,
    timeline: null,
    hoverIndex: null,
    hoverAnchor: null,
    hoverKeyboard: false,
    hoverFrame: 0,
    windows: [],
    entityNames: new Map(),
    topTab: 'cpu',
    processNodes: [],
    processTotal: null,
    processByParent: new Map(),
    processChildren: new Map(),
    processExpanded: new Set(),
    processQuery: '',
    processTimer: 0,
    processInitialized: false,
    processLastQuery: '',
    processFlat: false,
    processRendered: 0,
    processIncluded: 0,
    processMatches: 0,
    incidentFilter: null,
    logs: [],
    logFilters: { query: '', level: 'all', source: 'all' },
    logTimer: 0,
    printTheme: null,
    failedSections: []
  };

  /* ------------------------------------------------------------------ */
  /* Defensive data helpers                                              */
  /* ------------------------------------------------------------------ */

  function def(obj, key, fallback) {
    if (obj && typeof obj === 'object' && Object.prototype.hasOwnProperty.call(obj, key) && obj[key] !== undefined) {
      return obj[key];
    }
    return fallback;
  }

  function asObject(value, fallback) {
    return value && typeof value === 'object' && !Array.isArray(value) ? value : fallback;
  }

  function asArray(value, fallback) {
    return Array.isArray(value) ? value : fallback;
  }

  function isNum(value) {
    return typeof value === 'number' && Number.isFinite(value);
  }

  function numOrNull(value) {
    return isNum(value) ? value : null;
  }

  function strOrNull(value) {
    if (typeof value === 'string') return value;
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
    return null;
  }

  function nonEmptyString(value) {
    var text = strOrNull(value);
    return text === null || text === '' ? null : text;
  }

  function textValue(value) {
    return value === null || value === undefined ? DASH : String(value);
  }

  function $(id) {
    return document.getElementById(id);
  }

  function clear(node) {
    if (!node) return;
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function add(parent) {
    for (var i = 1; i < arguments.length; i += 1) {
      var child = arguments[i];
      if (child) parent.appendChild(child);
    }
    return parent;
  }

  function dashSpan() {
    var span = el('span', 'unavailable', DASH);
    span.title = 'Unavailable';
    span.setAttribute('aria-label', 'Unavailable');
    return span;
  }

  function safe(label, fn, target) {
    try {
      fn();
    } catch (error) {
      state.failedSections.push(label);
      try {
        if (window.console && console.error) console.error('[SARF report] ' + label, error);
      } catch (ignored) { /* Console may be unavailable. */ }
      if (target) {
        clear(target);
        target.appendChild(unavailableState(
          'Section unavailable',
          'This section could not be rendered from the embedded data. Other sections remain available.'
        ));
      }
    }
  }

  /* ------------------------------------------------------------------ */
  /* Formatting                                                          */
  /* ------------------------------------------------------------------ */

  var IEC_UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'];

  function decimal(value, digits) {
    if (!isNum(value)) return null;
    var text = value.toFixed(digits);
    if (text.indexOf('.') !== -1) {
      text = text.replace(/0+$/, '').replace(/\.$/, '');
    }
    return text;
  }

  function fmtCount(value) {
    if (!isNum(value)) return null;
    var rounded = Math.round(value);
    try {
      return rounded.toLocaleString();
    } catch (error) {
      return String(rounded);
    }
  }

  function fmtBytes(value) {
    if (!isNum(value)) return null;
    if (value === 0) return '0 B';
    var negative = value < 0;
    var absolute = Math.abs(value);
    var unit = 0;
    while (absolute >= 1024 && unit < IEC_UNITS.length - 1) {
      absolute /= 1024;
      unit += 1;
    }
    var digits = unit === 0 ? 0 : absolute >= 100 ? 0 : absolute >= 10 ? 1 : 2;
    return (negative ? '-' : '') + decimal(absolute, digits) + ' ' + IEC_UNITS[unit];
  }

  function fmtRate(value) {
    var bytes = fmtBytes(value);
    return bytes === null ? null : bytes + '/s';
  }

  function fmtPct(value, digits) {
    var number = decimal(value, digits === undefined ? 1 : digits);
    return number === null ? null : number + '%';
  }

  function fmtSignedPct(value) {
    if (!isNum(value)) return null;
    var sign = value > 0 ? '+' : '';
    return sign + decimal(value, 1) + '%';
  }

  function fmtNumber(value, digits) {
    return decimal(value, digits === undefined ? 2 : digits);
  }

  function fmtDuration(seconds) {
    if (!isNum(seconds) || seconds < 0) return null;
    var total = Math.round(seconds);
    if (total < 60) return total + 's';
    var days = Math.floor(total / 86400);
    var hours = Math.floor((total % 86400) / 3600);
    var minutes = Math.floor((total % 3600) / 60);
    var secs = total % 60;
    if (days > 0) return days + 'd ' + hours + 'h ' + minutes + 'm';
    if (hours > 0) return hours + 'h ' + minutes + 'm' + (secs ? ' ' + secs + 's' : '');
    return minutes + 'm ' + secs + 's';
  }

  var fullDateFormatter = makeDateFormatter({ year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  var shortDateFormatter = makeDateFormatter({ month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  var clockFormatter = makeDateFormatter({ hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  var hourFormatter = makeDateFormatter({ hour: '2-digit', minute: '2-digit', hour12: false });
  var dayFormatter = makeDateFormatter({ month: 'short', day: '2-digit' });

  function makeDateFormatter(options) {
    try {
      return new Intl.DateTimeFormat(undefined, options);
    } catch (error) {
      return null;
    }
  }

  function toDate(value) {
    var date;
    if (isNum(value)) {
      date = new Date(value / 1000000);
    } else if (typeof value === 'string') {
      var parsed = Date.parse(value);
      if (!Number.isFinite(parsed)) return null;
      date = new Date(parsed);
    } else {
      return null;
    }
    return isNaN(date.getTime()) ? null : date;
  }

  function toTimestamp(value) {
    if (isNum(value)) return value;
    var date = toDate(value);
    return date ? date.getTime() * 1000000 : null;
  }

  function metaWindowSeconds(meta) {
    var seconds = def(meta, 'window_secs', null);
    if (isNum(seconds)) return seconds;
    var since = toTimestamp(def(meta, 'since', null));
    var until = toTimestamp(def(meta, 'until', null));
    if (since === null || until === null) return null;
    return (until - since) / 1000000000;
  }

  function pad2(value) {
    return value < 10 ? '0' + value : String(value);
  }

  function manualStamp(date, short) {
    var clock = pad2(date.getHours()) + ':' + pad2(date.getMinutes()) + ':' + pad2(date.getSeconds());
    if (short) return date.toLocaleString(undefined, { month: 'short' }) + ' ' + pad2(date.getDate()) + ', ' + clock;
    return date.getFullYear() + '-' + pad2(date.getMonth() + 1) + '-' + pad2(date.getDate()) + ' ' + clock;
  }

  function fmtStamp(ns) {
    var date = toDate(ns);
    if (!date) return null;
    try {
      if (fullDateFormatter) return fullDateFormatter.format(date);
    } catch (error) { /* Fall through to the local formatter. */ }
    return manualStamp(date, false);
  }

  function fmtShortStamp(ns) {
    var date = toDate(ns);
    if (!date) return null;
    try {
      if (shortDateFormatter) return shortDateFormatter.format(date);
    } catch (error) { /* Fall through to the local formatter. */ }
    return manualStamp(date, true);
  }

  function fmtClock(ns) {
    var date = toDate(ns);
    if (!date) return null;
    try {
      if (clockFormatter) return clockFormatter.format(date);
    } catch (error) { /* Fall through. */ }
    return pad2(date.getHours()) + ':' + pad2(date.getMinutes()) + ':' + pad2(date.getSeconds());
  }

  function fmtHour(ns) {
    var date = toDate(ns);
    if (!date) return null;
    try {
      if (hourFormatter) return hourFormatter.format(date);
    } catch (error) { /* Fall through. */ }
    return pad2(date.getHours()) + ':' + pad2(date.getMinutes());
  }

  function fmtDay(ns) {
    var date = toDate(ns);
    if (!date) return null;
    try {
      if (dayFormatter) return dayFormatter.format(date);
    } catch (error) { /* Fall through. */ }
    return date.toLocaleString(undefined, { month: 'short' }) + ' ' + pad2(date.getDate());
  }

  function fmtTick(ns, spanNs) {
    if (!toDate(ns)) return null;
    if (isNum(spanNs) && spanNs >= 86400000000000) return fmtDay(ns);
    return fmtHour(ns);
  }

  function durationBetween(start, end) {
    if (!isNum(start) || !isNum(end) || end < start) return null;
    return fmtDuration((end - start) / 1000000000);
  }

  function confidencePercent(value) {
    if (!isNum(value)) return null;
    var percent = value <= 1 ? value * 100 : value;
    return Math.max(0, Math.min(100, percent));
  }

  function metricFormat(metric) {
    var name = String(metric || '').toLowerCase();
    if (!name) return 'number';
    if (/(^|_)bps$/.test(name) || name.indexOf('bytes_per_sec') !== -1 || name.indexOf('_rate') !== -1) return 'rate';
    if (name === 'memory' || name === 'io_read' || name === 'io_write' || name === 'net_rx' || name === 'net_tx') return 'bytes';
    if (name.indexOf('bytes') !== -1 || /(^|_)bytes?$/.test(name)) return 'bytes';
    if (name.indexOf('pct') !== -1 || name.indexOf('percent') !== -1 || name.indexOf('psi_') === 0 || name === 'cpu' || name === 'mem') return 'pct';
    if (name === 'load' || name === 'load1') return 'number';
    return 'number';
  }

  function contributorMetricFormat(windowMetric) {
    var name = String(windowMetric || '').toLowerCase();
    if (name === 'memory' || name === 'psi_memory' || name === 'io_read' || name === 'io_write' || name === 'net_rx' || name === 'net_tx') {
      return 'bytes';
    }
    return 'cpu';
  }

  function formatMetricValue(metric, value) {
    if (!isNum(value)) return null;
    var kind = metricFormat(metric);
    if (kind === 'bytes') return fmtBytes(value);
    if (kind === 'rate') return fmtRate(value);
    if (kind === 'pct') return fmtPct(value);
    return fmtNumber(value, 2);
  }

  function metricLabel(metric) {
    var name = strOrNull(metric);
    if (name === null || name === '') return 'Unspecified metric';
    return METRIC_LABELS[name] || name;
  }

  function seriesValue(series, value) {
    if (!isNum(value)) return null;
    if (series.format === 'pct') return fmtPct(value);
    if (series.format === 'bytes') return fmtBytes(value);
    if (series.format === 'rate') return fmtRate(value);
    return fmtNumber(value, 2);
  }

  function timezoneName() {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || null;
    } catch (error) {
      return null;
    }
  }

  /* ------------------------------------------------------------------ */
  /* Visual helpers                                                      */
  /* ------------------------------------------------------------------ */

  function statusTone(value) {
    var text = String(value === null || value === undefined ? '' : value).trim().toLowerCase();
    if (!text) return 'neutral';
    if (/^(ok|available|yes|true|enabled|detected|running|active|healthy|success|configured|permitted|present)$/.test(text)) return 'ok';
    if (/(denied|forbidden|error|failed|failure|critical|panic|fatal)/.test(text)) return 'danger';
    if (/(partial|degraded|unknown|not configured|disabled|unavailable|missing|not available|not detected|not_detected|^no$|^false$)/.test(text)) return 'warn';
    return 'info';
  }

  function levelTone(value) {
    var text = String(value === null || value === undefined ? '' : value).trim().toLowerCase();
    if (/^(error|err|fatal|panic|crit|critical|alert|emerg|emergency)$/.test(text)) return 'danger';
    if (/^(warn|warning)$/.test(text)) return 'warn';
    if (/^(info|notice|information)$/.test(text)) return 'info';
    if (/^(debug|trace)$/.test(text)) return 'neutral';
    return 'neutral';
  }

  function coverageTone(value) {
    var text = String(value === null || value === undefined ? '' : value).trim().toLowerCase();
    if (text === 'ok') return 'ok';
    if (text === 'partial') return 'warn';
    if (text === 'degraded') return 'danger';
    return 'neutral';
  }

  function setStatusChip(node, text, tone) {
    if (!node) return;
    node.classList.remove('tone-ok', 'tone-warn', 'tone-danger', 'tone-info', 'tone-neutral', 'tone-accent');
    node.classList.add('tone-' + (tone || 'neutral'));
    node.textContent = textValue(text);
  }

  function statusChip(value) {
    var text = strOrNull(value);
    var chip = el('span', 'status-chip');
    if (text === null) {
      chip.classList.add('tone-neutral');
      chip.appendChild(dashSpan());
    } else {
      chip.classList.add('tone-' + statusTone(text));
      chip.textContent = text;
    }
    return chip;
  }

  function makeChip(value, tone) {
    var text = strOrNull(value);
    var chip = el('span', 'chip');
    if (tone) chip.classList.add('tone-' + tone);
    if (text === null) {
      chip.appendChild(dashSpan());
    } else {
      chip.textContent = text;
    }
    return chip;
  }

  function setAside(node, value, label, note) {
    if (!node) return;
    clear(node);
    var valueNodeEl = el('span', 'aside-value');
    if (value === null || value === undefined) {
      valueNodeEl.appendChild(dashSpan());
    } else {
      valueNodeEl.textContent = String(value);
    }
    node.appendChild(valueNodeEl);
    node.appendChild(el('span', 'aside-label', label));
    if (note) node.appendChild(el('span', 'aside-note', note));
  }

  function setTabCount(id, value) {
    var node = $(id);
    if (!node) return;
    if (!isNum(value)) {
      node.textContent = '';
      return;
    }
    var count = Math.round(value);
    node.textContent = count > 999 ? '999+' : String(count);
  }

  function makeEmpty(title, text, symbol) {
    var box = el('div', 'empty-state');
    var mark = el('div', 'empty-mark', symbol || '\u2205');
    mark.setAttribute('aria-hidden', 'true');
    var copy = el('div');
    copy.appendChild(el('p', 'empty-title', title));
    copy.appendChild(el('p', 'empty-text', text));
    box.appendChild(mark);
    box.appendChild(copy);
    return box;
  }

  function unavailableState(title, text) {
    var box = makeEmpty(title, text, '!');
    box.className = 'unavailable-state';
    return box;
  }

  function buildTable(columns, caption) {
    var table = el('table', 'data-table');
    if (caption) {
      var captionEl = el('caption', 'sr-only', caption);
      table.appendChild(captionEl);
    }
    var thead = el('thead');
    var headRow = el('tr');
    columns.forEach(function (column) {
      var th = el('th', column.cls || '', column.label);
      th.scope = 'col';
      if (column.title) th.title = column.title;
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    var tbody = el('tbody');
    table.appendChild(thead);
    table.appendChild(tbody);
    return { table: table, tbody: tbody };
  }

  function tableCell(row, content, className) {
    var cell = el('td', className || '');
    if (content !== null && content !== undefined) {
      if (typeof content === 'string') {
        cell.textContent = content;
      } else {
        cell.appendChild(content);
      }
    }
    row.appendChild(cell);
    return cell;
  }

  function valueCell(row, formatted, className) {
    var cell = el('td', className || '');
    if (formatted === null || formatted === undefined) {
      cell.appendChild(dashSpan());
    } else {
      cell.textContent = String(formatted);
    }
    row.appendChild(cell);
    return cell;
  }

  function stackCell(row, lines, className) {
    var cell = el('td', className || '');
    var stack = el('div', 'cell-stack');
    lines.forEach(function (line) {
      var span = el('span');
      if (line.label) span.appendChild(document.createTextNode(line.label + ' '));
      if (line.value === null || line.value === undefined) {
        span.appendChild(dashSpan());
      } else {
        span.appendChild(document.createTextNode(String(line.value)));
      }
      stack.appendChild(span);
    });
    cell.appendChild(stack);
    row.appendChild(cell);
    return cell;
  }

  function appender(parent, value) {
    if (value === null || value === undefined) {
      parent.appendChild(dashSpan());
    } else if (typeof value === 'string') {
      parent.appendChild(document.createTextNode(value));
    } else {
      parent.appendChild(value);
    }
  }

  function appendBoundedNote(parent, shown, total, noun) {
    if (!parent || !isNum(total) || total <= shown) return;
    parent.appendChild(el('p', 'render-note', 'Showing ' + fmtCount(shown) + ' of ' + fmtCount(total) + ' ' + noun + ' (display cap).'));
  }

  function prepareWrap(container, className) {
    clear(container);
    var wrap = el('div', className || 'table-scroll');
    container.appendChild(wrap);
    return wrap;
  }

  /* ------------------------------------------------------------------ */
  /* Boot & global wiring                                                */
  /* ------------------------------------------------------------------ */

  function start() {
    try {
      setupTheme();
      setupNavigation();
      setupPrint();
      window.addEventListener('resize', scheduleChartResize);
      window.addEventListener('scroll', function () {
        if (state.hoverIndex !== null) clearHover();
      }, { passive: true });

      var payload = readPayload();
      if (!payload) {
        setFooter(null);
        applyInitialHash();
        return;
      }

      state.data = payload;
      state.meta = asObject(def(payload, 'meta', null), {});
      state.summary = asObject(def(payload, 'summary', null), {});
      state.tz = timezoneName();
      state.windows = Array.isArray(def(payload, 'windows', null)) ? payload.windows : [];
      state.entityNames = buildEntityNames();

      safe('header', renderHeader, $('masthead-meta'));
      safe('summary', renderSummary, $('summary-kpis'));
      safe('windows', renderWindows, $('windows-list'));
      safe('timeline', renderTimeline, $('timeline-charts'));
      safe('top', renderTop, $('top-panels'));
      safe('processes', initProcesses, $('process-view'));
      safe('incidents', renderIncidents, $('incidents-table-wrap'));
      safe('logs', initLogs, $('log-table-wrap'));
      safe('events', renderEvents, $('events-table-wrap'));
      safe('coverage', renderCoverage, $('collectors-wrap'));
      setFooter(payload);
      setupChartObserver();
      applyInitialHash();
    } catch (error) {
      showFatal('The report could not be initialised.', error);
      try {
        if (window.console && console.error) console.error('[SARF report] fatal', error);
      } catch (ignored) { /* No console. */ }
      setFooter(null);
    }
  }

  function readPayload() {
    var node = $('sarf-data');
    if (!node) {
      showFatal('The embedded report payload is missing from this file.', null);
      return null;
    }
    var text = node.textContent || '';
    try {
      var parsed = JSON.parse(text);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('payload is not an object');
      }
      return parsed;
    } catch (error) {
      showFatal('The embedded report data could not be parsed. The report file may be truncated, malformed, or edited. No observations were rendered.', error);
      return null;
    }
  }

  function showFatal(message, error) {
    var banner = $('global-error');
    var detail = $('global-error-detail');
    if (detail) {
      var text = message;
      if (error && error.name) text += ' (' + error.name + ')';
      detail.textContent = text;
    }
    if (banner) banner.hidden = false;
    if ($('summary-lede')) {
      $('summary-lede').textContent = 'The report payload could not be read. No observations are displayed.';
    }
  }

  function setFooter(payload) {
    var footer = $('footer-meta');
    if (!footer) return;
    if (!payload) {
      footer.textContent = 'Payload unavailable \u00b7 No observations rendered \u00b7 No network access';
      return;
    }
    var parts = [];
    var meta = asObject(def(payload, 'meta', null), {});
    var product = nonEmptyString(def(meta, 'product', null)) || 'SARF';
    var version = nonEmptyString(def(meta, 'version', null));
    parts.push(product + (version ? ' ' + version : ''));
    var generated = fmtStamp(def(meta, 'generated', null));
    if (generated) parts.push('Generated ' + generated);
    if (state.tz) parts.push(state.tz);
    parts.push('Rendered locally from embedded JSON; no network access');
    footer.textContent = parts.join(' \u00b7 ');
  }

  function setupTheme() {
    var theme = document.documentElement.getAttribute('data-theme');
    if (theme !== 'light' && theme !== 'dark') {
      theme = 'dark';
      try {
        var stored = localStorage.getItem(THEME_KEY);
        if (stored === 'light' || stored === 'dark') theme = stored;
      } catch (error) { /* Storage is optional. */ }
    }
    applyTheme(theme, false);
    var button = $('theme-toggle');
    if (button) {
      button.addEventListener('click', function () {
        var current = document.documentElement.getAttribute('data-theme');
        applyTheme(current === 'light' ? 'dark' : 'light', true);
      });
    }
  }

  function applyTheme(theme, persist) {
    document.documentElement.setAttribute('data-theme', theme);
    state.theme = theme;
    var button = $('theme-toggle');
    var label = $('theme-toggle-label');
    var light = theme === 'light';
    if (button) {
      button.setAttribute('aria-pressed', light ? 'true' : 'false');
      button.setAttribute('aria-label', light ? 'Switch to dark theme' : 'Switch to light theme');
    }
    if (label) label.textContent = light ? 'Dark' : 'Light';
    if (persist) {
      try {
        localStorage.setItem(THEME_KEY, theme);
      } catch (error) { /* Storage can be unavailable. */ }
    }
    if (state.charts.length) {
      window.requestAnimationFrame(function () {
        redrawCharts();
      });
    }
  }

  function setupNavigation() {
    var tablist = $('report-tabs');
    if (!tablist) return;
    state.tabs = Array.prototype.slice.call(tablist.querySelectorAll('[role="tab"]'));
    state.tabs.forEach(function (tab) {
      tab.addEventListener('click', function () {
        activateView(tab.getAttribute('data-view'), { updateHash: true });
      });
      tab.addEventListener('keydown', onNavTabKey);
    });
    window.addEventListener('hashchange', function () {
      var view = viewFromHash();
      if (view) activateView(view, { updateHash: false, scroll: true });
    });
  }

  function onNavTabKey(event) {
    var current = state.tabs.indexOf(document.activeElement);
    if (current === -1) return;
    var next = current;
    if (event.key === 'ArrowRight') next = (current + 1) % state.tabs.length;
    else if (event.key === 'ArrowLeft') next = (current - 1 + state.tabs.length) % state.tabs.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = state.tabs.length - 1;
    else return;
    event.preventDefault();
    var tab = state.tabs[next];
    tab.focus();
    activateView(tab.getAttribute('data-view'), { updateHash: true });
  }

  function viewFromHash() {
    var raw = '';
    try {
      raw = decodeURIComponent((window.location.hash || '').replace(/^#/, '')).toLowerCase();
    } catch (error) {
      raw = (window.location.hash || '').replace(/^#/, '').toLowerCase();
    }
    return VIEW_ALIASES[raw] || null;
  }

  function applyInitialHash() {
    var view = viewFromHash();
    if (view) {
      activateView(view, { updateHash: false });
    } else if (window.location.hash && window.location.hash !== '#main') {
      activateView('summary', { updateHash: true });
    }
  }

  function activateView(view, options) {
    var opts = options || {};
    var normalized = VIEW_ALIASES[view] || 'summary';
    state.view = normalized;
    state.tabs.forEach(function (tab) {
      var active = tab.getAttribute('data-view') === normalized;
      tab.setAttribute('aria-selected', active ? 'true' : 'false');
      tab.tabIndex = active ? 0 : -1;
      tab.classList.toggle('is-active', active);
    });
    var panels = ['summary', 'windows', 'timeline', 'top', 'processes', 'incidents', 'logs', 'coverage'];
    panels.forEach(function (name) {
      var panel = $('panel-' + name);
      if (!panel) return;
      panel.hidden = name !== normalized;
    });
    if (opts.updateHash) {
      try {
        window.history.replaceState(null, '', '#' + normalized);
      } catch (error) {
        try {
          window.location.hash = normalized;
        } catch (ignored) { /* Navigation is optional. */ }
      }
    }
    if (opts.scroll) {
      var activePanel = $('panel-' + normalized);
      if (activePanel) {
        try {
          activePanel.scrollIntoView({ behavior: 'auto', block: 'start' });
        } catch (error) {
          activePanel.scrollIntoView();
        }
        try {
          activePanel.focus({ preventScroll: true });
        } catch (error) {
          activePanel.focus();
        }
      }
    }
    if (normalized === 'timeline') {
      try {
        resizeAllCharts(true);
      } catch (error) {
        // A later animation frame and ResizeObserver retry the layout.
      }
      window.requestAnimationFrame(function () {
        window.requestAnimationFrame(function () {
          resizeAllCharts(true);
        });
      });
    } else if (state.hoverIndex !== null) {
      clearHover();
    }
  }

  function setupPrint() {
    window.addEventListener('beforeprint', function () {
      if (state.printTheme === null) {
        state.printTheme = document.documentElement.getAttribute('data-theme');
      }
      document.body.classList.add('printing');
      if (state.printTheme === 'dark') {
        document.documentElement.setAttribute('data-theme', 'light');
      }
      clearHover();
      void document.body.offsetHeight;
      resizeAllCharts(true);
    });
    window.addEventListener('afterprint', function () {
      document.body.classList.remove('printing');
      if (state.printTheme) {
        document.documentElement.setAttribute('data-theme', state.printTheme);
      }
      state.printTheme = null;
      window.requestAnimationFrame(function () {
        resizeAllCharts(true);
      });
    });
  }

  /* ------------------------------------------------------------------ */
  /* Header & summary                                                    */
  /* ------------------------------------------------------------------ */

  function buildEntityNames() {
    var names = new Map();
    if (!state.data) return names;
    var processes = asObject(def(state.data, 'processes', null), null);
    var nodes = processes ? asArray(def(processes, 'nodes', null), []) : [];
    nodes.forEach(function (node) {
      if (!node || typeof node !== 'object') return;
      var id = strOrNull(def(node, 'id', null));
      var name = nonEmptyString(def(node, 'comm', null)) || nonEmptyString(def(node, 'executable', null));
      if (id !== null && name !== null && !names.has(id)) names.set(id, name);
    });
    var top = asObject(def(state.data, 'top', null), null);
    if (top) {
      ['cpu', 'memory', 'io', 'network'].forEach(function (metric) {
        var list = asArray(def(top, metric, null), []);
        list.forEach(function (entity) {
          if (!entity || typeof entity !== 'object') return;
          var id = strOrNull(def(entity, 'entity_id', null));
          var name = nonEmptyString(def(entity, 'name', null));
          if (id !== null && name !== null && !names.has(id)) names.set(id, name);
        });
      });
    }
    return names;
  }

  function renderHeader() {
    var meta = state.meta;
    var product = nonEmptyString(def(meta, 'product', null)) || 'SARF';
    var version = nonEmptyString(def(meta, 'version', null));
    var generated = fmtStamp(def(meta, 'generated', null));
    var since = fmtStamp(def(meta, 'since', null));
    var until = fmtStamp(def(meta, 'until', null));

    var brandProduct = $('brand-product');
    if (brandProduct) brandProduct.textContent = product + (version ? ' ' + version : '');
    var productShort = $('meta-product-short');
    if (productShort) productShort.textContent = product;

    var subtitle = $('masthead-subtitle');
    if (subtitle) {
      subtitle.textContent = product + (version ? ' ' + version : '') + ' \u00b7 local forensic observation artifact. ' +
        'Every figure describes the embedded report window only.';
    }

    var metaHost = $('masthead-meta');
    if (metaHost) {
      clear(metaHost);
      appendMetaItem(metaHost, 'Generated', generated);
      appendMetaItem(metaHost, 'Window', since && until ? since + ' \u2192 ' + until : null);
      appendMetaItem(metaHost, 'Host', nonEmptyString(def(meta, 'hostname', null)));
    }

    var sim = $('simulated-badge');
    if (sim) sim.hidden = def(meta, 'simulated', false) !== true;

    var stampProduct = $('stamp-product');
    if (stampProduct) stampProduct.textContent = product;
    var stampVersion = $('stamp-version');
    if (stampVersion) stampVersion.textContent = textValue(version);
    var stampGenerated = $('stamp-generated');
    if (stampGenerated) stampGenerated.textContent = textValue(generated);

    var strip = $('window-strip');
    if (strip) {
      clear(strip);
      var windowText = since && until ? since + ' \u2192 ' + until : null;
      appendStripItem(strip, 'Observation window', windowText);
      appendStripItem(strip, 'Window length', fmtDuration(metaWindowSeconds(meta)));
      appendStripItem(strip, 'Generated locally', generated);
    }
  }

  function appendMetaItem(parent, label, value) {
    var item = el('div', 'meta-item');
    item.appendChild(el('span', 'meta-label', label));
    var valueEl = el('span', 'meta-value');
    appender(valueEl, value === null || value === '' ? null : value);
    item.appendChild(valueEl);
    parent.appendChild(item);
  }

  function appendStripItem(parent, label, value) {
    var item = el('div', 'strip-item');
    item.appendChild(el('span', 'strip-label', label));
    var valueEl = el('span', 'strip-value');
    appender(valueEl, value);
    item.appendChild(valueEl);
    parent.appendChild(item);
  }

  function renderSummary() {
    var summary = state.summary;
    var meta = state.meta;
    var since = fmtStamp(def(meta, 'since', null));
    var until = fmtStamp(def(meta, 'until', null));
    var lede = $('summary-lede');
    if (lede) {
      lede.textContent = since && until
        ? 'Observed host and workload activity from ' + since + ' to ' + until + '. Figures below are measurements of that window, not host guarantees.'
        : 'Observed host and workload activity for the embedded report window. Missing values remain unavailable.';
    }

    renderSummaryHealth();
    renderKpis();
    renderHostFacts();
    renderCoverageHealth();

    var units = $('units-note');
    if (units) {
      var note = nonEmptyString(def(meta, 'units_note', null));
      units.textContent = note || 'CPU and PSI values are percentages of one logical core. Memory and byte rates use IEC units; rates are bytes per second. A dash means unavailable, never zero.';
    }
  }

  function coverageStatusText() {
    var status = strOrNull(def(state.summary, 'coverage', null));
    return status === null || status === '' ? null : status;
  }

  function renderSummaryHealth() {
    var target = $('summary-health');
    if (!target) return;
    clear(target);
    var status = coverageStatusText();
    var row = el('div', 'health-status-row');
    var chip = statusChip(status);
    chip.textContent = status === null ? DASH : status;
    row.appendChild(chip);
    row.appendChild(el('span', 'aside-label', 'Coverage status'));
    target.appendChild(row);
    updateNavCoverage();
  }

  function updateNavCoverage() {
    var status = coverageStatusText();
    setStatusChip($('nav-coverage'), 'Coverage ' + (status === null ? DASH : status), coverageTone(status));
  }

  function kpiShell(index, label, tone) {
    var card = el('article', 'kpi' + (tone ? ' is-' + tone : ''));
    var head = el('div', 'kpi-label');
    head.appendChild(el('span', '', label));
    head.appendChild(el('span', 'kpi-index', index));
    card.appendChild(head);
    return card;
  }

  function addKpiValue(card, value, unit) {
    var valueEl = el('div', 'kpi-value');
    if (value === null || value === undefined) {
      valueEl.appendChild(dashSpan());
    } else {
      valueEl.appendChild(document.createTextNode(String(value)));
    }
    if (unit) valueEl.appendChild(el('span', 'kpi-unit', unit));
    card.appendChild(valueEl);
  }

  function addKpiSub(card, text) {
    card.appendChild(el('p', 'kpi-sub', text));
  }

  function countOrFallback(summaryKey, fallback) {
    var value = numOrNull(def(state.summary, summaryKey, null));
    if (value !== null && value > 0) return value;
    if (isNum(fallback)) return fallback;
    return value;
  }

  function renderKpis() {
    var target = $('summary-kpis');
    if (!target) return;
    clear(target);
    var summary = state.summary;
    var avg = numOrNull(def(summary, 'host_cpu_avg_pct', null));
    var max = numOrNull(def(summary, 'host_cpu_max_pct', null));
    var memPeak = numOrNull(def(summary, 'host_mem_used_max_bytes', null));
    var memTotal = numOrNull(def(summary, 'host_mem_total_bytes', null));
    var windowsArray = asArray(def(state.data, 'windows', null), null);
    var incidentsArray = asArray(def(state.data, 'incidents', null), null);
    var processObject = asObject(def(state.data, 'processes', null), null);
    var processNodes = processObject ? asArray(def(processObject, 'nodes', null), []) : null;
    var processTotal = processObject ? numOrNull(def(processObject, 'total', null)) : null;
    var incidentCount = countOrFallback('incident_count', incidentsArray === null ? null : incidentsArray.length);
    var windowCount = countOrFallback('window_count', windowsArray === null ? null : windowsArray.length);
    var processCount = countOrFallback(
      'process_count',
      processTotal !== null && processTotal > 0 ? processTotal : (processNodes === null ? null : processNodes.length)
    );
    var logCount = numOrNull(def(summary, 'log_count', null));
    var eventCount = numOrNull(def(summary, 'event_count', null));

    var cpuCard = kpiShell('01', 'Host CPU');
    addKpiValue(cpuCard, fmtPct(avg), 'of one core');
    addKpiSub(cpuCard, 'peak ' + (fmtPct(max) === null ? DASH : fmtPct(max)) + ' \u00b7 average and maximum across the window');
    target.appendChild(cpuCard);

    var memCard = kpiShell('02', 'Memory peak');
    addKpiValue(memCard, fmtBytes(memPeak));
    addKpiSub(memCard, memTotal === null ? 'installed total unavailable' : 'of ' + fmtBytes(memTotal) + ' installed');
    target.appendChild(memCard);

    var pressureCard = kpiShell('03', 'Pressure peaks (PSI)');
    var rows = el('div', 'kpi-rows');
    [
      ['CPU', numOrNull(def(summary, 'psi_cpu_max', null))],
      ['Memory', numOrNull(def(summary, 'psi_memory_max', null))],
      ['I/O', numOrNull(def(summary, 'psi_io_max', null))]
    ].forEach(function (pair) {
      var row = el('div', 'kpi-row');
      row.appendChild(el('span', '', pair[0]));
      row.appendChild(el('strong', '', fmtPct(pair[1]) === null ? DASH : fmtPct(pair[1])));
      rows.appendChild(row);
    });
    pressureCard.appendChild(rows);
    addKpiSub(pressureCard, 'percent of one logical core');
    target.appendChild(pressureCard);

    var incidentCard = kpiShell('04', 'Incidents');
    addKpiValue(incidentCard, fmtCount(incidentCount));
    addKpiSub(incidentCard, 'recorded in the incident register');
    target.appendChild(incidentCard);

    var windowCard = kpiShell('05', 'Attribution windows');
    addKpiValue(windowCard, fmtCount(windowCount));
    addKpiSub(windowCard, 'high/low usage intervals with evidence');
    target.appendChild(windowCard);

    var processCard = kpiShell('06', 'Processes');
    addKpiValue(processCard, fmtCount(processCount));
    addKpiSub(processCard, 'observed in the report window');
    target.appendChild(processCard);

    var logCard = kpiShell('07', 'Stored logs');
    addKpiValue(logCard, fmtCount(logCount));
    addKpiSub(logCard, (fmtCount(eventCount) === null ? DASH : fmtCount(eventCount)) + ' events \u00b7 embedded sample may be bounded');
    target.appendChild(logCard);

    var coverageCard = kpiShell('08', 'Coverage health', coverageTone(coverageStatusText()));
    addKpiValue(coverageCard, coverageStatusText() === null ? null : coverageStatusText().toUpperCase());
    var coverage = asObject(def(state.data, 'coverage', null), null);
    var collectors = coverage ? asArray(def(coverage, 'collectors', null), null) : null;
    var gaps = coverage ? asArray(def(coverage, 'gaps', null), null) : null;
    var openGaps = gaps === null ? null : gaps.filter(function (gap) {
      return gap && typeof gap === 'object' && !isNum(def(gap, 'resolved', null));
    }).length;
    addKpiSub(coverageCard,
      (collectors === null ? DASH : fmtCount(collectors.length)) + ' collectors \u00b7 ' +
      (openGaps === null ? DASH : fmtCount(openGaps)) + ' open gaps');
    target.appendChild(coverageCard);
  }

  function renderHostFacts() {
    var list = $('host-facts');
    if (!list) return;
    clear(list);
    var meta = state.meta;
    var since = fmtStamp(def(meta, 'since', null));
    var until = fmtStamp(def(meta, 'until', null));
    var seconds = metaWindowSeconds(meta);
    appendFact(list, 'Hostname', nonEmptyString(def(meta, 'hostname', null)));
    appendFact(list, 'Boot ID', nonEmptyString(def(meta, 'boot_id', null)));
    appendFact(list, 'Kernel', nonEmptyString(def(meta, 'kernel', null)));
    appendFact(list, 'Architecture', nonEmptyString(def(meta, 'architecture', null)));
    appendFact(list, 'Report window', since && until ? since + ' \u2192 ' + until : null);
    appendFact(list, 'Window length', fmtDuration(seconds));
    appendFact(list, 'Generated', fmtStamp(def(meta, 'generated', null)));
    appendFact(list, 'Local timezone', state.tz);
  }

  function appendFact(list, label, value) {
    list.appendChild(el('dt', '', label));
    var dd = el('dd');
    appender(dd, value);
    list.appendChild(dd);
  }

  function renderCoverageHealth() {
    var target = $('coverage-health');
    if (!target) return;
    clear(target);
    var status = coverageStatusText();
    var tone = coverageTone(status);
    var row = el('div', 'health-status-row');
    var chip = statusChip(status);
    chip.textContent = status === null ? DASH : status;
    row.appendChild(chip);
    target.appendChild(row);

    var descriptions = {
      ok: 'Collectors reported healthy coverage for this window. Review the ledger before treating the absence of an observation as evidence.',
      partial: 'Some sources were partially available or incomplete. Findings may under-represent activity on the host.',
      degraded: 'Coverage is materially reduced. Absence of activity in this report should not be read as absence on the host.',
      neutral: 'Coverage status was not reported. Treat the report as incomplete until the collector ledger is reviewed.'
    };
    var statusKey = status === null ? 'neutral' : String(status).trim().toLowerCase();
    if (!descriptions[statusKey]) statusKey = 'neutral';
    target.appendChild(el('p', 'health-copy', descriptions[statusKey]));

    var coverage = asObject(def(state.data, 'coverage', null), null);
    var collectors = coverage ? asArray(def(coverage, 'collectors', null), null) : null;
    var gaps = coverage ? asArray(def(coverage, 'gaps', null), null) : null;
    var integrations = coverage ? asArray(def(coverage, 'integrations', null), null) : null;
    var openGaps = gaps === null ? null : gaps.filter(function (gap) {
      return gap && typeof gap === 'object' && !isNum(def(gap, 'resolved', null));
    }).length;
    var availabilityIssues = collectors === null ? null : collectors.filter(function (collector) {
      if (!collector || typeof collector !== 'object') return false;
      var availability = strOrNull(def(collector, 'availability', null));
      return availability === null || !/^(ok|available|yes|true|enabled|running|active|healthy)$/i.test(availability.trim());
    }).length;

    var stats = el('div', 'health-stats');
    appendHealthStat(stats, collectors === null ? null : fmtCount(collectors.length), 'Collectors');
    appendHealthStat(stats, integrations === null ? null : fmtCount(integrations.length), 'Integrations');
    appendHealthStat(stats, openGaps === null ? null : fmtCount(openGaps), 'Open gaps');
    appendHealthStat(stats, availabilityIssues === null ? null : fmtCount(availabilityIssues), 'Availability issues');
    target.appendChild(stats);

    var sentence = el('p', 'health-copy');
    sentence.textContent = 'Unavailable is not zero. A dash means the value was not reported, lacked permission, or the source was absent.';
    target.appendChild(sentence);

    var link = el('a', 'text-link', 'Open coverage & gaps');
    link.href = '#coverage';
    target.appendChild(link);
  }

  function appendHealthStat(parent, value, label) {
    var stat = el('div', 'health-stat');
    var valueEl = el('span', 'health-stat-value');
    appender(valueEl, value);
    stat.appendChild(valueEl);
    stat.appendChild(el('span', 'health-stat-label', label));
    parent.appendChild(stat);
  }

  /* ------------------------------------------------------------------ */
  /* Attribution windows                                                 */
  /* ------------------------------------------------------------------ */

  function renderWindows() {
    var target = $('windows-list');
    if (!target) return;
    clear(target);
    var raw = def(state.data, 'windows', null);
    var countNode = $('windows-count');
    var tabCount = $('tab-count-windows');

    if (!Array.isArray(raw)) {
      target.appendChild(unavailableState('Attribution windows unavailable', 'The embedded report does not contain an attribution-window array. This is unavailable data, not evidence that nothing happened.'));
      setAside(countNode, null, 'windows');
      setTabCount('tab-count-windows', null);
      return;
    }
    var valid = raw.filter(function (window) {
      return window && typeof window === 'object';
    }).sort(function (a, b) {
      var aStart = numOrNull(def(a, 'start', null));
      var bStart = numOrNull(def(b, 'start', null));
      if (aStart === null && bStart === null) return 0;
      if (aStart === null) return 1;
      if (bStart === null) return -1;
      return aStart - bStart;
    });

    setAside(countNode, fmtCount(valid.length), 'attribution windows');
    setTabCount('tab-count-windows', valid.length);

    if (valid.length === 0) {
      target.appendChild(makeEmpty(
        'No attribution windows detected',
        'SARF did not detect a high or low usage window in this report window. That can mean normal operation, thresholds that were not crossed, or insufficient coverage. Review Coverage & gaps before drawing a conclusion.'
      ));
      return;
    }

    var shown = Math.min(valid.length, WINDOW_CAP);
    var fragment = document.createDocumentFragment();
    for (var i = 0; i < shown; i += 1) {
      fragment.appendChild(renderWindowCard(valid[i], i));
    }
    target.appendChild(fragment);
    appendBoundedNote(target, shown, valid.length, 'attribution windows');
  }

  function renderWindowCard(window, index) {
    var kindRaw = String(def(window, 'kind', '')).toLowerCase();
    var kind = kindRaw === 'high' || kindRaw === 'low' ? kindRaw : 'unknown';
    var metric = strOrNull(def(window, 'metric', null));
    var start = numOrNull(def(window, 'start', null));
    var end = numOrNull(def(window, 'end', null));
    var value = numOrNull(def(window, 'value', null));
    var baseline = numOrNull(def(window, 'baseline', null));
    var change = numOrNull(def(window, 'change_pct', null));
    var confidence = confidencePercent(def(window, 'confidence', null));

    var card = el('article', 'window-card' + (kind !== 'unknown' ? ' kind-' + kind : ''));
    var head = el('div', 'window-head');
    var heading = el('div', 'window-heading');
    var kicker = el('div', 'window-kicker');
    kicker.appendChild(el('span', 'window-number', 'W-' + pad2(index + 1)));
    var badgeClass = kind === 'high' ? 'kind-high' : kind === 'low' ? 'kind-low' : 'kind-unknown';
    kicker.appendChild(el('span', 'badge-kind ' + badgeClass, kind === 'unknown' ? 'UNCLASSIFIED' : kind.toUpperCase()));
    if (metric) {
      var metricChip = makeChip(metric, 'tone-neutral');
      kicker.appendChild(metricChip);
    }
    heading.appendChild(kicker);

    var title = el('h3', 'window-title', metricLabel(metric));
    if (metric) {
      var code = el('code', 'window-metric-code', metric);
      title.appendChild(code);
    }
    heading.appendChild(title);

    var timeLine = el('p', 'window-time');
    timeLine.appendChild(document.createTextNode('Start '));
    timeLine.appendChild(el('strong', '', fmtStamp(start) === null ? DASH : fmtStamp(start)));
    timeLine.appendChild(document.createTextNode(' \u2192 end '));
    timeLine.appendChild(el('strong', '', fmtStamp(end) === null ? (end === null ? 'open / not observed' : DASH) : fmtStamp(end)));
    heading.appendChild(timeLine);

    var duration = durationBetween(start, end);
    var durationBox = el('div', 'window-duration');
    durationBox.appendChild(el('span', 'duration-value', duration === null ? DASH : duration));
    durationBox.appendChild(el('span', 'duration-label', 'Observed span'));
    head.appendChild(heading);
    head.appendChild(durationBox);
    card.appendChild(head);

    var metrics = el('div', 'window-metrics');
    appendWindowMetric(metrics, 'Window value', formatMetricValue(metric, value), 'measured in the window');
    appendWindowMetric(metrics, 'Baseline', formatMetricValue(metric, baseline), 'expected reference');
    var changeText = fmtSignedPct(change);
    var changeMetric = appendWindowMetric(metrics, 'Change vs baseline', changeText, 'direction only, not judgement');
    var changeValue = changeMetric.querySelector('.window-metric-value');
    if (changeValue && isNum(change) && change !== 0) {
      changeValue.classList.add(change > 0 ? 'change-up' : 'change-down');
    }
    appendWindowMetric(metrics, 'Association confidence', confidence === null ? null : Math.round(confidence) + '%', 'not causation');
    card.appendChild(metrics);

    var confidenceBlock = el('div', 'confidence-block');
    var confidenceHead = el('div', 'confidence-head');
    confidenceHead.appendChild(el('span', 'confidence-label', 'Association confidence'));
    confidenceHead.appendChild(el('span', 'confidence-value', confidence === null ? DASH : Math.round(confidence) + '%'));
    confidenceBlock.appendChild(confidenceHead);
    var bar = el('div', 'confidence-bar');
    bar.setAttribute('role', 'img');
    if (confidence === null) {
      bar.setAttribute('aria-label', 'Association confidence unavailable. This is association confidence, not causation.');
    } else {
      bar.setAttribute('aria-label', 'Association confidence ' + Math.round(confidence) + ' percent. This is association confidence, not causation.');
    }
    var fill = el('span', 'confidence-fill' + (kind === 'high' ? ' fill-high' : kind === 'low' ? ' fill-low' : ''));
    if (confidence !== null) fill.style.width = confidence.toFixed(1) + '%';
    bar.appendChild(fill);
    confidenceBlock.appendChild(bar);
    confidenceBlock.appendChild(el('p', 'confidence-note', 'Association confidence, not causation. It reflects temporal overlap and recorded contribution only.'));
    card.appendChild(confidenceBlock);

    card.appendChild(renderContributors(window, metric));
    card.appendChild(renderWindowSupport(window, metric));
    return card;
  }

  function appendWindowMetric(parent, label, value, note) {
    var metric = el('div', 'window-metric');
    metric.appendChild(el('span', 'window-metric-label', label));
    var valueEl = el('span', 'window-metric-value');
    appender(valueEl, value);
    metric.appendChild(valueEl);
    if (note) metric.appendChild(el('span', 'window-metric-note', note));
    parent.appendChild(metric);
    return metric;
  }

  function renderContributors(window, metric) {
    var section = el('section', 'contributors-block');
    section.setAttribute('aria-label', 'Ranked contributors');
    var head = el('div', 'subsection-head');
    head.appendChild(el('h4', '', 'Ranked contributors'));
    var raw = def(window, 'contributors', null);
    var countLabel = Array.isArray(raw) ? raw.length : null;
    var basis = contributorMetricFormat(metric) === 'bytes' ? 'memory bytes' : 'CPU % of one core';
    head.appendChild(el('span', '', 'ranked by ' + basis + ' \u00b7 ' + (countLabel === null ? 'unavailable' : fmtCount(countLabel) + ' recorded')));
    section.appendChild(head);

    if (!Array.isArray(raw)) {
      section.appendChild(el('p', 'inline-empty', 'Contributor detail unavailable for this window.'));
      return section;
    }
    if (raw.length === 0) {
      section.appendChild(el('p', 'inline-empty', 'No entity contributions were recorded for this window.'));
      return section;
    }

    var list = el('div', 'contributor-list');
    raw.slice(0, 20).forEach(function (contributor, index) {
      if (!contributor || typeof contributor !== 'object') return;
      var name = nonEmptyString(def(contributor, 'name', null)) ||
        nonEmptyString(def(contributor, 'entity_id', null)) || 'Unidentified entity';
      var kind = nonEmptyString(def(contributor, 'kind', null));
      var tool = nonEmptyString(def(contributor, 'tool', null));
      var value = numOrNull(def(contributor, 'value', null));
      var share = numOrNull(def(contributor, 'share_pct', null));
      var evidence = def(contributor, 'evidence', null);

      var card = el('article', 'contributor');
      var top = el('div', 'contributor-top');
      var heading = el('div', 'contributor-heading');
      heading.appendChild(el('span', 'contributor-rank', pad2(index + 1)));
      var nameBlock = el('div');
      nameBlock.appendChild(el('div', 'contributor-name', name));
      var meta = el('div', 'contributor-meta');
      if (kind) meta.appendChild(makeChip(kind, 'tone-neutral'));
      if (tool) meta.appendChild(makeChip('tool \u00b7 ' + tool, 'tone-accent'));
      if (meta.childNodes.length) nameBlock.appendChild(meta);
      heading.appendChild(nameBlock);
      top.appendChild(heading);

      var figures = el('div', 'contributor-figures');
      var valueText = formatMetricValue(contributorMetricFormat(metric), value);
      figures.appendChild(el('span', 'contributor-value', valueText === null ? DASH : valueText));
      figures.appendChild(el('span', 'contributor-share', share === null ? 'share ' + DASH : 'share ' + fmtPct(share)));
      top.appendChild(figures);
      card.appendChild(top);

      if (share !== null) {
        var track = el('div', 'share-track');
        var fill = el('span', 'share-fill');
        fill.style.width = Math.max(0, Math.min(100, share)).toFixed(1) + '%';
        track.appendChild(fill);
        card.appendChild(track);
      }

      if (Array.isArray(evidence) && evidence.length) {
        card.appendChild(evidenceList(evidence, 8));
        if (evidence.length > 8) card.appendChild(el('p', 'render-note', 'Showing 8 of ' + fmtCount(evidence.length) + ' evidence bullets.'));
      } else if (Array.isArray(evidence)) {
        card.appendChild(el('p', 'inline-empty', 'No evidence bullets recorded.'));
      } else {
        card.appendChild(el('p', 'inline-empty', 'Evidence bullets unavailable.'));
      }
      list.appendChild(card);
    });
    section.appendChild(list);
    if (raw.length > 20) {
      section.appendChild(el('p', 'render-note', 'Showing 20 of ' + fmtCount(raw.length) + ' recorded contributors (display cap).'));
    }
    return section;
  }

  function evidenceList(items, cap) {
    var list = el('ul', 'evidence-list');
    var seen = 0;
    for (var i = 0; i < items.length && seen < cap; i += 1) {
      var text = nonEmptyString(items[i]);
      if (text === null) continue;
      list.appendChild(el('li', '', text));
      seen += 1;
    }
    return list;
  }

  function renderWindowSupport(window, metric) {
    var grid = el('div', 'window-support');

    var evidenceCard = el('section', 'support-card');
    var evidenceHead = el('div', 'support-head');
    evidenceHead.appendChild(el('span', '', 'Window evidence'));
    var windowEvidence = def(window, 'evidence', null);
    evidenceHead.appendChild(el('span', 'support-count', Array.isArray(windowEvidence) ? fmtCount(windowEvidence.length) : DASH));
    evidenceCard.appendChild(evidenceHead);
    if (Array.isArray(windowEvidence)) {
      if (windowEvidence.length) {
        var evidence = evidenceList(windowEvidence, 10);
        evidence.className = 'window-evidence';
        evidenceCard.appendChild(evidence);
        if (windowEvidence.length > 10) evidenceCard.appendChild(el('p', 'inline-empty', 'Showing 10 of ' + fmtCount(windowEvidence.length) + ' evidence notes.'));
      } else {
        evidenceCard.appendChild(el('p', 'inline-empty', 'No window-level evidence notes recorded.'));
      }
    } else {
      evidenceCard.appendChild(el('p', 'inline-empty', 'Window evidence unavailable.'));
    }
    grid.appendChild(evidenceCard);

    var logCard = el('section', 'support-card');
    var logHead = el('div', 'support-head');
    logHead.appendChild(el('span', '', 'Correlated logs'));
    var rawLogs = def(window, 'logs', null);
    logHead.appendChild(el('span', 'support-count', Array.isArray(rawLogs) ? fmtCount(rawLogs.length) : DASH));
    logCard.appendChild(logHead);
    if (!Array.isArray(rawLogs)) {
      logCard.appendChild(el('p', 'inline-empty', 'Correlated logs unavailable.'));
    } else if (rawLogs.length === 0) {
      logCard.appendChild(el('p', 'inline-empty', 'No logs correlated to this window.'));
    } else {
      var lines = el('div', 'log-lines');
      rawLogs.slice(0, WINDOW_LOG_CAP).forEach(function (log) {
        if (log && typeof log === 'object') lines.appendChild(renderMiniLog(log));
      });
      logCard.appendChild(lines);
      if (rawLogs.length > WINDOW_LOG_CAP) {
        logCard.appendChild(el('p', 'inline-empty', 'Showing ' + WINDOW_LOG_CAP + ' of ' + fmtCount(rawLogs.length) + ' correlated log entries.'));
      }
    }
    grid.appendChild(logCard);

    var eventCard = el('section', 'support-card');
    var eventHead = el('div', 'support-head');
    eventHead.appendChild(el('span', '', 'Events'));
    var rawEvents = def(window, 'events', null);
    eventHead.appendChild(el('span', 'support-count', Array.isArray(rawEvents) ? fmtCount(rawEvents.length) : DASH));
    eventCard.appendChild(eventHead);
    if (!Array.isArray(rawEvents)) {
      eventCard.appendChild(el('p', 'inline-empty', 'Correlated events unavailable.'));
    } else if (rawEvents.length === 0) {
      eventCard.appendChild(el('p', 'inline-empty', 'No events correlated to this window.'));
    } else {
      rawEvents.slice(0, WINDOW_EVENT_CAP).forEach(function (event) {
        if (event && typeof event === 'object') eventCard.appendChild(renderEventLine(event));
      });
      if (rawEvents.length > WINDOW_EVENT_CAP) {
        eventCard.appendChild(el('p', 'inline-empty', 'Showing ' + WINDOW_EVENT_CAP + ' of ' + fmtCount(rawEvents.length) + ' correlated events.'));
      }
    }
    grid.appendChild(eventCard);

    if (metric) grid.setAttribute('data-metric', metric);
    return grid;
  }

  function renderMiniLog(log) {
    var line = el('div', 'log-line');
    var meta = el('div', 'log-line-meta');
    meta.appendChild(el('span', '', fmtStamp(def(log, 'wall', null)) === null ? DASH : fmtStamp(def(log, 'wall', null))));
    var level = nonEmptyString(def(log, 'level', null));
    if (level) meta.appendChild(makeChip(level, levelTone(level)));
    var source = nonEmptyString(def(log, 'source_id', null));
    if (source) meta.appendChild(el('span', '', source));
    if (def(log, 'truncated', false) === true) {
      var flag = makeChip('truncated');
      flag.classList.add('truncated-flag');
      meta.appendChild(flag);
    }
    line.appendChild(meta);
    var message = strOrNull(def(log, 'message', null));
    line.appendChild(el('div', 'log-line-message' + (message === '' ? ' is-empty' : ''), message === null || message === '' ? '(empty message)' : message));
    return line;
  }

  function renderEventLine(event) {
    var line = el('div', 'event-line');
    line.appendChild(el('span', 'event-time', fmtStamp(def(event, 'wall', null)) === null ? DASH : fmtStamp(def(event, 'wall', null))));
    var severity = nonEmptyString(def(event, 'severity', null));
    line.appendChild(makeChip(severity === null ? DASH : severity, levelTone(severity)));
    var kind = nonEmptyString(def(event, 'kind', null));
    line.appendChild(el('span', 'event-kind', kind === null ? '(kind unavailable)' : kind));
    var entity = nonEmptyString(def(event, 'entity_id', null));
    if (entity) line.appendChild(el('span', 'entity-ref', entity));
    return line;
  }

  /* ------------------------------------------------------------------ */
  /* Timeline                                                            */
  /* ------------------------------------------------------------------ */

  function renderTimeline() {
    var grid = $('timeline-charts');
    if (!grid) return;
    clear(grid);
    state.charts = [];
    var raw = def(state.data, 'series', null);
    var note = $('timeline-note');
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      grid.appendChild(unavailableState('Timeline unavailable', 'The embedded report does not contain a series object. Missing telemetry is unavailable, not zero.'));
      setAside($('timeline-count'), null, 'samples');
      if (note) note.textContent = 'No timeline sample data was embedded.';
      return;
    }
    var normalized = normalizeTimeline(raw);
    if (!normalized) {
      grid.appendChild(unavailableState('Timeline unavailable', 'The embedded series has no valid sample timestamps.'));
      setAside($('timeline-count'), null, 'samples');
      if (note) note.textContent = 'No valid timeline sample times were reported.';
      return;
    }
    if (!normalized.hasAnyValue) {
      grid.appendChild(makeEmpty(
        'No metric values reported',
        'Sample times were embedded, but every host metric value is unavailable. Missing values are not drawn as zero.'
      ));
      setAside($('timeline-count'), fmtCount(normalized.times.length), 'sample times');
      if (note) note.textContent = 'Sample times are present; all metric values are unavailable.';
      return;
    }

    state.timeline = normalized;
    setAside(
      $('timeline-count'),
      fmtCount(normalized.times.length),
      'samples',
      normalized.times.length > CHART_POINT_CAP ? 'peak-preserving decimation' : null
    );

    if (note) {
      var parts = [fmtCount(normalized.times.length) + ' samples', 'local time'];
      var windowCount = state.windows.filter(function (window) {
        return window && typeof window === 'object' && isNum(def(window, 'start', null));
      }).length;
      if (windowCount > 0) {
        parts.push(fmtCount(windowCount) + ' attribution window' + (windowCount === 1 ? '' : 's') + ' shaded (red high, teal low)');
      } else {
        parts.push('no attribution windows to shade');
      }
      if (normalized.times.length > CHART_POINT_CAP) {
        parts.push('peak-preserving decimation above ' + fmtCount(CHART_POINT_CAP) + ' samples');
      }
      note.textContent = parts.join(' \u00b7 ');
    }

    CHART_SPECS.forEach(function (spec) {
      var chart = buildChart(spec, normalized);
      state.charts.push(chart);
      grid.appendChild(chart.card);
    });

    var gridPointerLeave = function () {
      clearHover();
    };
    grid.addEventListener('pointerleave', gridPointerLeave);
    grid.addEventListener('pointercancel', gridPointerLeave);
    window.requestAnimationFrame(function () {
      resizeAllCharts();
    });
  }

  function normalizeTimeline(raw) {
    var timesRaw = def(raw, 'timestamps', null);
    if (!Array.isArray(timesRaw)) return null;
    var indices = [];
    for (var i = 0; i < timesRaw.length; i += 1) {
      if (isNum(timesRaw[i])) indices.push(i);
    }
    if (indices.length === 0) return null;
    var sorted = indices.slice();
    var ascending = true;
    for (var j = 1; j < sorted.length; j += 1) {
      if (timesRaw[sorted[j]] < timesRaw[sorted[j - 1]]) {
        ascending = false;
        break;
      }
    }
    if (!ascending) {
      sorted.sort(function (a, b) {
        return timesRaw[a] - timesRaw[b];
      });
    }
    var times = sorted.map(function (index) { return timesRaw[index]; });
    var values = {};
    var hasAnyValue = false;
    Object.keys(SERIES).forEach(function (key) {
      var rawValues = def(raw, key, null);
      if (!Array.isArray(rawValues)) {
        values[key] = sorted.map(function () { return null; });
        return;
      }
      values[key] = sorted.map(function (index) {
        var value = rawValues[index];
        if (isNum(value)) {
          hasAnyValue = true;
          return value;
        }
        return null;
      });
    });
    return { times: times, values: values, hasAnyValue: hasAnyValue };
  }

  function buildChart(spec, timeline) {
    var card = el('article', 'chart-card' + (spec.wide ? ' wide' : ''));
    var head = el('div', 'chart-head');
    head.appendChild(el('h3', 'chart-title', spec.title));
    var noteId = 'chart-note-' + spec.id;
    var note = el('p', 'chart-note', spec.note);
    note.id = noteId;
    head.appendChild(note);
    card.appendChild(head);

    var legend = el('div', 'chart-legend');
    legend.setAttribute('role', 'group');
    legend.setAttribute('aria-label', 'Series visibility for ' + spec.title);
    var plot = el('div', 'chart-plot');
    var canvas = el('canvas', 'chart-canvas');
    canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label', spec.title + ' timeline. Use the left and right arrow keys to inspect samples. Missing values are gaps, not zero.');
    canvas.setAttribute('aria-describedby', noteId);
    canvas.tabIndex = 0;
    var overlay = el('div', 'chart-overlay');
    overlay.hidden = true;
    plot.appendChild(canvas);
    plot.appendChild(overlay);

    var chart = {
      spec: spec,
      card: card,
      canvas: canvas,
      ctx: canvas.getContext('2d'),
      base: document.createElement('canvas'),
      baseCtx: null,
      plot: plot,
      overlay: overlay,
      legend: legend,
      times: timeline.times,
      values: timeline.values,
      visible: new Set(spec.keys),
      series: spec.keys.map(function (key) {
        var definition = SERIES[key];
        return {
          key: key,
          label: definition.label,
          color: definition.color,
          format: definition.format,
          axis: definition.axis
        };
      }),
      hasData: {},
      decimated: new Map(),
      layout: null,
      width: 0,
      height: 0,
      dpr: 0,
      foot: null
    };
    chart.baseCtx = chart.base.getContext('2d');

    chart.series.forEach(function (series) {
      var visible = chart.values[series.key].some(function (value) { return isNum(value); });
      chart.hasData[series.key] = visible;
      var button = el('button', 'legend-toggle');
      button.type = 'button';
      button.setAttribute('aria-pressed', 'true');
      button.setAttribute('aria-label', 'Toggle ' + series.label + ' series');
      var swatch = el('span', 'legend-swatch');
      swatch.style.background = 'var(' + series.color + ')';
      swatch.style.setProperty('--swatch', 'var(' + series.color + ')');
      button.appendChild(swatch);
      button.appendChild(el('span', '', series.label));
      button.addEventListener('click', function () {
        if (chart.visible.has(series.key)) chart.visible.delete(series.key);
        else chart.visible.add(series.key);
        var pressed = chart.visible.has(series.key);
        button.setAttribute('aria-pressed', pressed ? 'true' : 'false');
        updateChartFoot(chart);
        updateChartOverlay(chart);
        if (chart.layout) {
          drawChartBase(chart);
          paintChart(chart);
        }
        if (state.hoverIndex !== null) rebuildTooltip();
      });
      legend.appendChild(button);
    });

    var foot = el('div', 'chart-foot');
    var sampleText = el('span', '', fmtCount(timeline.times.length) + ' samples');
    var hint = el('span', '', 'Hover or focus \u00b7 arrow keys inspect');
    foot.appendChild(sampleText);
    foot.appendChild(hint);
    chart.foot = sampleText;

    card.appendChild(legend);
    card.appendChild(plot);
    card.appendChild(foot);
    wireChart(chart);
    updateChartFoot(chart);
    updateChartOverlay(chart);
    return chart;
  }

  function updateChartFoot(chart) {
    if (!chart.foot) return;
    var hidden = chart.series.filter(function (series) {
      return !chart.visible.has(series.key);
    }).length;
    chart.foot.textContent = fmtCount(chart.times.length) + ' samples' +
      (hidden ? ' \u00b7 ' + hidden + ' series hidden' : '');
  }

  function wireChart(chart) {
    var canvas = chart.canvas;
    canvas.addEventListener('pointermove', function (event) {
      var index = indexForClientX(chart, event.clientX);
      if (index !== null) setHover(index, { x: event.clientX, y: event.clientY }, false);
    });
    canvas.addEventListener('pointerdown', function (event) {
      var index = indexForClientX(chart, event.clientX);
      if (index !== null) setHover(index, { x: event.clientX, y: event.clientY }, false);
    });
    canvas.addEventListener('focus', function () {
      if (state.hoverIndex !== null) return;
      var index = nearestCenterIndex(chart);
      if (index !== null) setHover(index, anchorForIndex(chart, index), true);
    });
    canvas.addEventListener('keydown', function (event) {
      handleChartKeydown(chart, event);
    });
    canvas.addEventListener('blur', function () {
      clearHover();
    });
  }

  function handleChartKeydown(chart, event) {
    var total = chart.times.length;
    if (!total) return;
    var index = state.hoverIndex;
    var step = event.shiftKey ? 10 : 1;
    if (event.key === 'ArrowRight') {
      index = index === null ? nearestCenterIndex(chart) : index + step;
    } else if (event.key === 'ArrowLeft') {
      index = index === null ? nearestCenterIndex(chart) : index - step;
    } else if (event.key === 'PageDown') {
      index = index === null ? nearestCenterIndex(chart) : index + Math.max(1, Math.floor(total / 20));
    } else if (event.key === 'PageUp') {
      index = index === null ? nearestCenterIndex(chart) : index - Math.max(1, Math.floor(total / 20));
    } else if (event.key === 'Home') {
      index = 0;
    } else if (event.key === 'End') {
      index = total - 1;
    } else if (event.key === 'Escape') {
      event.preventDefault();
      clearHover();
      return;
    } else {
      return;
    }
    event.preventDefault();
    index = Math.max(0, Math.min(total - 1, index));
    setHover(index, anchorForIndex(chart, index), true);
    announceHover(index);
  }

  function nearestCenterIndex(chart) {
    if (!chart.times.length) return null;
    var middle = chart.times[0] + (chart.times[chart.times.length - 1] - chart.times[0]) / 2;
    return nearestTimeIndex(chart.times, middle);
  }

  function nearestTimeIndex(times, target) {
    if (!times.length) return null;
    var low = 0;
    var high = times.length - 1;
    while (low < high) {
      var mid = Math.floor((low + high) / 2);
      if (times[mid] < target) low = mid + 1;
      else high = mid;
    }
    if (low > 0 && Math.abs(times[low - 1] - target) <= Math.abs(times[low] - target)) return low - 1;
    return low;
  }

  function indexForClientX(chart, clientX) {
    var layout = chart.layout;
    if (!layout || !chart.times.length) return null;
    var rect = chart.canvas.getBoundingClientRect();
    var x = clientX - rect.left;
    var clamped = Math.max(layout.left, Math.min(layout.right, x));
    var first = chart.times[0];
    var last = chart.times[chart.times.length - 1];
    var target = last === first ? first : first + ((clamped - layout.left) / layout.plotW) * (last - first);
    return nearestTimeIndex(chart.times, target);
  }

  function anchorForIndex(chart, index) {
    var layout = chart.layout;
    if (!layout) return { x: 12, y: 12 };
    var rect = chart.canvas.getBoundingClientRect();
    var x = xForTime(chart, chart.times[index]);
    return { x: rect.left + x, y: rect.top + 16 };
  }

  function setHover(index, anchor, keyboard) {
    if (index === null || index < 0 || index >= (state.timeline ? state.timeline.times.length : 0)) return;
    state.hoverIndex = index;
    state.hoverAnchor = anchor;
    state.hoverKeyboard = keyboard === true;
    if (state.hoverKeyboard) announceHover(index);
    if (state.hoverFrame) return;
    state.hoverFrame = window.requestAnimationFrame(function () {
      state.hoverFrame = 0;
      state.charts.forEach(function (chart) {
        if (chart.layout) paintChart(chart);
      });
      rebuildTooltip();
    });
  }

  function clearHover() {
    if (state.hoverIndex === null) {
      var tip = $('chart-tooltip');
      if (tip) tip.hidden = true;
      return;
    }
    state.hoverIndex = null;
    state.hoverAnchor = null;
    state.hoverKeyboard = false;
    if (state.hoverFrame) {
      window.cancelAnimationFrame(state.hoverFrame);
      state.hoverFrame = 0;
    }
    state.charts.forEach(function (chart) {
      if (chart.layout) paintChart(chart);
    });
    var tooltip = $('chart-tooltip');
    if (tooltip) tooltip.hidden = true;
  }

  function rebuildTooltip() {
    var tooltip = $('chart-tooltip');
    if (!tooltip) return;
    if (state.hoverIndex === null || !state.timeline) {
      tooltip.hidden = true;
      return;
    }
    var time = state.timeline.times[state.hoverIndex];
    if (!isNum(time)) {
      tooltip.hidden = true;
      return;
    }
    clear(tooltip);
    tooltip.appendChild(el('div', 'tooltip-time', fmtStamp(time) === null ? DASH : fmtStamp(time)));
    var rows = 0;
    state.charts.forEach(function (chart) {
      chart.series.forEach(function (series) {
        if (!chart.visible.has(series.key)) return;
        var value = chart.values[series.key][state.hoverIndex];
        var formatted = seriesValue(series, value);
        var row = el('div', 'tooltip-row');
        var swatch = el('span', 'tooltip-swatch');
        swatch.style.background = 'var(' + series.color + ')';
        row.appendChild(swatch);
        row.appendChild(el('span', 'tooltip-label', series.label));
        var valueEl = el('span', 'tooltip-value');
        appender(valueEl, formatted);
        row.appendChild(valueEl);
        tooltip.appendChild(row);
        rows += 1;
      });
    });
    if (rows === 0) {
      tooltip.appendChild(el('p', 'tooltip-empty', 'All series are hidden. Use the chart legends to show a trace.'));
    }
    var covering = windowsCovering(time);
    covering.slice(0, 3).forEach(function (window) {
      var kind = String(def(window, 'kind', '')).toUpperCase();
      var metric = strOrNull(def(window, 'metric', null));
      tooltip.appendChild(el('p', 'tooltip-window', (kind === 'HIGH' || kind === 'LOW' ? kind : 'UNCLASSIFIED') + ' window \u00b7 ' + metricLabel(metric)));
    });
    tooltip.hidden = false;
    positionTooltip(tooltip);
  }

  function positionTooltip(tooltip) {
    var anchor = state.hoverAnchor || { x: 12, y: 12 };
    var rect = tooltip.getBoundingClientRect();
    var width = rect.width;
    var height = rect.height;
    var left = anchor.x + 16;
    var top = anchor.y + 16;
    if (left + width > window.innerWidth - 8) left = anchor.x - width - 16;
    if (top + height > window.innerHeight - 8) top = anchor.y - height - 16;
    left = Math.max(8, Math.min(left, window.innerWidth - width - 8));
    top = Math.max(8, Math.min(top, window.innerHeight - height - 8));
    tooltip.style.left = Math.round(left) + 'px';
    tooltip.style.top = Math.round(top) + 'px';
  }

  function windowsCovering(time) {
    var until = toTimestamp(def(state.meta, 'until', null));
    return state.windows.filter(function (window) {
      if (!window || typeof window !== 'object') return false;
      var start = numOrNull(def(window, 'start', null));
      if (start === null) return false;
      var end = numOrNull(def(window, 'end', null));
      if (end === null) end = until === null ? start : until;
      return time >= start && time <= end;
    });
  }

  function announceHover(index) {
    var announcer = $('chart-announcer');
    if (!announcer || !state.timeline) return;
    var time = state.timeline.times[index];
    var parts = [fmtStamp(time) === null ? DASH : fmtStamp(time)];
    state.charts.forEach(function (chart) {
      chart.series.forEach(function (series) {
        if (!chart.visible.has(series.key)) return;
        var formatted = seriesValue(series, chart.values[series.key][index]);
        parts.push(series.label + ': ' + (formatted === null ? 'unavailable' : formatted));
      });
    });
    announcer.textContent = parts.join('. ');
  }

  function decimate(values, times, maxPoints) {
    var total = values.length;
    if (total <= maxPoints) {
      var points = [];
      for (var i = 0; i < total; i += 1) {
        points.push({ t: times[i], v: values[i] });
      }
      return { points: points, decimated: false };
    }
    var buckets = Math.max(1, Math.floor(maxPoints / 2));
    var step = total / buckets;
    var out = [];
    for (var bucket = 0; bucket < buckets; bucket += 1) {
      var start = Math.floor(bucket * step);
      var end = Math.min(total, Math.floor((bucket + 1) * step));
      if (start >= end) continue;
      var minIndex = -1;
      var maxIndex = -1;
      for (var index = start; index < end; index += 1) {
        var value = values[index];
        if (!isNum(value)) continue;
        if (minIndex === -1 || value < values[minIndex]) minIndex = index;
        if (maxIndex === -1 || value > values[maxIndex]) maxIndex = index;
      }
      if (minIndex === -1) {
        out.push({ t: times[start], v: null });
      } else if (minIndex === maxIndex) {
        out.push({ t: times[minIndex], v: values[minIndex] });
      } else if (minIndex < maxIndex) {
        out.push({ t: times[minIndex], v: values[minIndex] });
        out.push({ t: times[maxIndex], v: values[maxIndex] });
      } else {
        out.push({ t: times[maxIndex], v: values[maxIndex] });
        out.push({ t: times[minIndex], v: values[minIndex] });
      }
    }
    return { points: out, decimated: true };
  }

  function chartData(chart, key) {
    if (!chart.decimated.has(key)) {
      chart.decimated.set(key, decimate(chart.values[key], chart.times, CHART_POINT_CAP));
    }
    return chart.decimated.get(key);
  }

  function setupChartObserver() {
    var grid = $('timeline-charts');
    if (!grid) return;
    if (state.chartObserver && state.chartObserver.disconnect) state.chartObserver.disconnect();
    if (typeof ResizeObserver === 'function') {
      state.chartObserver = new ResizeObserver(function () {
        scheduleChartResize();
      });
      state.chartObserver.observe(grid);
    }
  }

  function scheduleChartResize() {
    if (state.chartResizeFrame) return;
    state.chartResizeFrame = window.requestAnimationFrame(function () {
      state.chartResizeFrame = 0;
      resizeAllCharts();
    });
  }

  function resizeAllCharts(force) {
    state.charts.forEach(function (chart) {
      resizeChart(chart, force === true);
    });
  }

  function redrawCharts() {
    state.charts.forEach(function (chart) {
      if (chart.layout) resizeChart(chart, true);
    });
  }

  function resizeChart(chart, force) {
    if (!chart || !chart.canvas || !chart.canvas.isConnected) return;
    if (!chart.canvas.getClientRects().length) return;
    var width = Math.max(60, Math.round(chart.canvas.clientWidth));
    var height = Math.max(60, Math.round(chart.canvas.clientHeight));
    if (width < 60 || height < 60) return;
    var dpr = Math.min(window.devicePixelRatio || 1, 2.5);
    if (!force && chart.width === width && chart.height === height && chart.dpr === dpr && chart.base.width) return;
    chart.width = width;
    chart.height = height;
    chart.dpr = dpr;
    [chart.canvas, chart.base].forEach(function (canvas) {
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
    });
    chart.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    chart.baseCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
    chart.layout = computeChartLayout(chart);
    updateChartOverlay(chart);
    drawChartBase(chart);
    paintChart(chart);
  }

  function computeChartLayout(chart) {
    var width = chart.width;
    var height = chart.height;
    var leftPad = chart.spec.leftFormat === 'rate' ? 64 : 44;
    var rightPad = chart.spec.rightFormat ? (chart.spec.rightFormat === 'bytes' ? 64 : 44) : 14;
    var top = 12;
    var bottom = height - 24;
    leftPad = Math.min(leftPad, Math.max(40, width * 0.28));
    rightPad = Math.min(rightPad, Math.max(30, width * 0.26));
    return {
      width: width,
      height: height,
      left: leftPad,
      right: width - rightPad,
      top: top,
      bottom: bottom,
      plotW: Math.max(1, width - leftPad - rightPad),
      plotH: Math.max(1, bottom - top)
    };
  }

  function themeColor(name) {
    try {
      var value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
      return value || '#888888';
    } catch (error) {
      return '#888888';
    }
  }

  function chartColors() {
    var colors = {
      grid: themeColor('--chart-grid'),
      axis: themeColor('--chart-axis'),
      high: themeColor('--marker-high'),
      low: themeColor('--marker-low'),
      surface: themeColor('--surface'),
      text: themeColor('--text'),
      crosshair: themeColor('--chart-crosshair')
    };
    colors.series = {};
    Object.keys(SERIES).forEach(function (key) {
      colors.series[key] = themeColor(SERIES[key].color);
    });
    return colors;
  }

  function drawChartBase(chart) {
    var ctx = chart.baseCtx;
    var layout = chart.layout;
    if (!ctx || !layout) return;
    var colors = chartColors();
    ctx.setTransform(chart.dpr, 0, 0, chart.dpr, 0, 0);
    ctx.clearRect(0, 0, layout.width, layout.height);

    var leftExtent = axisExtent(chart, 'left', chart.spec.leftFormat);
    var rightExtent = axisExtent(chart, 'right', chart.spec.rightFormat);
    var rightVisible = chart.series.some(function (series) {
      return series.axis === 'right' && chart.visible.has(series.key) && chart.hasData[series.key];
    });

    drawWindowBands(chart, ctx, layout, colors);
    drawChartGrid(chart, ctx, layout, colors, leftExtent, rightExtent, rightVisible);
    drawChartSeries(chart, ctx, layout, colors, leftExtent, rightExtent);
    ctx.setTransform(chart.dpr, 0, 0, chart.dpr, 0, 0);
  }

  function axisExtent(chart, axis, format) {
    var max = 0;
    var found = false;
    chart.series.forEach(function (series) {
      if (series.axis !== axis || !chart.visible.has(series.key)) return;
      var values = chart.values[series.key];
      for (var i = 0; i < values.length; i += 1) {
        if (isNum(values[i])) {
          found = true;
          if (values[i] > max) max = values[i];
        }
      }
    });
    if (!found) return { min: 0, max: 1, hasData: false };
    if (format === 'pct') {
      return { min: 0, max: max <= 100 ? 100 : niceMax(max * 1.01), hasData: true };
    }
    return { min: 0, max: niceMax(max * 1.01), hasData: true };
  }

  function niceMax(value) {
    if (!isNum(value) || value <= 0) return 1;
    var exponent = Math.floor(Math.log10(value));
    var base = Math.pow(10, exponent);
    var scaled = value / base;
    var steps = [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10];
    for (var i = 0; i < steps.length; i += 1) {
      if (scaled <= steps[i]) return steps[i] * base;
    }
    return 10 * base;
  }

  function drawWindowBands(chart, ctx, layout, colors) {
    var windows = state.windows.filter(function (window) {
      return window && typeof window === 'object' && isNum(def(window, 'start', null));
    });
    if (!windows.length || !chart.times.length) return;
    var until = toTimestamp(def(state.meta, 'until', null));
    ctx.save();
    ctx.beginPath();
    ctx.rect(layout.left, layout.top, layout.plotW, layout.plotH);
    ctx.clip();
    windows.forEach(function (window) {
      var start = def(window, 'start', null);
      var end = numOrNull(def(window, 'end', null));
      if (end === null) end = until === null ? start : until;
      var x1 = xForTime(chart, start);
      var x2 = xForTime(chart, end);
      if (x2 < layout.left || x1 > layout.right) return;
      x1 = Math.max(layout.left, Math.min(layout.right, x1));
      x2 = Math.max(layout.left, Math.min(layout.right, x2));
      if (x2 - x1 < 1.5) x2 = Math.min(layout.right, x1 + 1.5);
      var color = String(def(window, 'kind', '')).toLowerCase() === 'low' ? colors.low : colors.high;
      ctx.globalAlpha = 0.075;
      ctx.fillStyle = color;
      ctx.fillRect(x1, layout.top, x2 - x1, layout.plotH);
      ctx.globalAlpha = 0.45;
      ctx.fillRect(x1, layout.top, Math.max(1, x2 - x1), 2);
      ctx.globalAlpha = 1;
    });
    ctx.restore();
  }

  function drawChartGrid(chart, ctx, layout, colors, leftExtent, rightExtent, rightVisible) {
    var divisions = 4;
    ctx.save();
    ctx.lineWidth = 1;
    ctx.font = '10px ' + MONO;
    ctx.textBaseline = 'middle';

    for (var i = 0; i <= divisions; i += 1) {
      var ratio = i / divisions;
      var y = layout.bottom - layout.plotH * ratio;
      ctx.strokeStyle = colors.grid;
      ctx.beginPath();
      ctx.moveTo(layout.left, y + 0.5);
      ctx.lineTo(layout.right, y + 0.5);
      ctx.stroke();
      ctx.fillStyle = colors.axis;
      ctx.textAlign = 'right';
      ctx.fillText(formatAxisLabel(leftExtent.min + (leftExtent.max - leftExtent.min) * ratio, chart.spec.leftFormat), layout.left - 7, y);
      if (chart.spec.rightFormat && rightVisible) {
        ctx.textAlign = 'left';
        ctx.fillText(formatAxisLabel(rightExtent.min + (rightExtent.max - rightExtent.min) * ratio, chart.spec.rightFormat), layout.right + 7, y);
      }
    }

    if (chart.times.length) {
      var first = chart.times[0];
      var last = chart.times[chart.times.length - 1];
      var span = last - first;
      for (var tick = 0; tick <= divisions; tick += 1) {
        var tickRatio = tick / divisions;
        var x = layout.left + layout.plotW * tickRatio;
        ctx.strokeStyle = colors.grid;
        ctx.beginPath();
        ctx.moveTo(x + 0.5, layout.top);
        ctx.lineTo(x + 0.5, layout.bottom);
        ctx.stroke();
        var time = first + span * tickRatio;
        ctx.fillStyle = colors.axis;
        ctx.textAlign = tick === 0 ? 'left' : tick === divisions ? 'right' : 'center';
        ctx.textBaseline = 'bottom';
        ctx.fillText(fmtTick(time, span) === null ? DASH : fmtTick(time, span), x, layout.height - 4);
      }
    }
    ctx.restore();
  }

  function formatAxisLabel(value, format) {
    if (format === 'pct') return fmtPct(value, Number.isInteger(value) ? 0 : 1);
    if (format === 'rate') return fmtRate(value);
    if (format === 'bytes') return fmtBytes(value);
    return fmtNumber(value, value !== 0 && Math.abs(value) < 10 ? 2 : 1);
  }

  function drawChartSeries(chart, ctx, layout, colors, leftExtent, rightExtent) {
    ctx.save();
    ctx.beginPath();
    ctx.rect(layout.left, layout.top, layout.plotW, layout.plotH);
    ctx.clip();
    chart.series.forEach(function (series) {
      if (!chart.visible.has(series.key)) return;
      var data = chartData(chart, series.key);
      var points = data.points;
      var extent = series.axis === 'right' ? rightExtent : leftExtent;
      ctx.strokeStyle = colors.series[series.key] || colors.text;
      ctx.lineWidth = 1.4;
      ctx.lineJoin = 'round';
      ctx.lineCap = 'round';
      var drawing = false;
      var lastPoint = null;
      for (var i = 0; i < points.length; i += 1) {
        var point = points[i];
        if (!isNum(point.v)) {
          if (drawing) {
            ctx.stroke();
            drawing = false;
          }
          lastPoint = null;
          continue;
        }
        var x = xForTime(chart, point.t);
        var y = yForValue(point.v, extent, layout);
        if (!drawing) {
          ctx.beginPath();
          ctx.moveTo(x, y);
          drawing = true;
        } else {
          ctx.lineTo(x, y);
        }
        lastPoint = { x: x, y: y };
      }
      if (drawing) ctx.stroke();

      if (!data.decimated && points.length <= 160) {
        ctx.fillStyle = colors.series[series.key] || colors.text;
        for (var p = 0; p < points.length; p += 1) {
          if (!isNum(points[p].v)) continue;
          var dotX = xForTime(chart, points[p].t);
          var dotY = yForValue(points[p].v, extent, layout);
          ctx.beginPath();
          ctx.arc(dotX, dotY, 1.8, 0, Math.PI * 2);
          ctx.fill();
        }
      }
      if (lastPoint) {
        ctx.fillStyle = colors.series[series.key] || colors.text;
        ctx.beginPath();
        ctx.arc(lastPoint.x, lastPoint.y, 2.2, 0, Math.PI * 2);
        ctx.fill();
      }
    });
    ctx.restore();
  }

  function xForTime(chart, time) {
    var layout = chart.layout;
    if (!layout || !chart.times.length) return 0;
    var first = chart.times[0];
    var last = chart.times[chart.times.length - 1];
    if (last === first) return layout.left + layout.plotW / 2;
    return layout.left + ((time - first) / (last - first)) * layout.plotW;
  }

  function yForValue(value, extent, layout) {
    var range = extent.max - extent.min;
    if (!(range > 0)) range = 1;
    return layout.bottom - ((value - extent.min) / range) * layout.plotH;
  }

  function paintChart(chart) {
    if (!chart.layout || !chart.base.width) return;
    var ctx = chart.ctx;
    var layout = chart.layout;
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, chart.canvas.width, chart.canvas.height);
    ctx.drawImage(chart.base, 0, 0);
    ctx.setTransform(chart.dpr, 0, 0, chart.dpr, 0, 0);
    if (state.hoverIndex === null || !state.timeline) return;
    var time = state.timeline.times[state.hoverIndex];
    if (!isNum(time)) return;
    var x = xForTime(chart, time);
    if (x < layout.left - 1 || x > layout.right + 1) return;
    var colors = chartColors();
    var leftExtent = axisExtent(chart, 'left', chart.spec.leftFormat);
    var rightExtent = axisExtent(chart, 'right', chart.spec.rightFormat);
    ctx.save();
    ctx.beginPath();
    ctx.rect(layout.left, layout.top, layout.plotW, layout.plotH);
    ctx.clip();
    ctx.strokeStyle = colors.crosshair;
    ctx.lineWidth = 1;
    ctx.setLineDash([3, 3]);
    ctx.beginPath();
    ctx.moveTo(x, layout.top);
    ctx.lineTo(x, layout.bottom);
    ctx.stroke();
    ctx.setLineDash([]);
    chart.series.forEach(function (series) {
      if (!chart.visible.has(series.key)) return;
      var value = chart.values[series.key][state.hoverIndex];
      if (!isNum(value)) return;
      var extent = series.axis === 'right' ? rightExtent : leftExtent;
      var y = yForValue(value, extent, layout);
      ctx.fillStyle = colors.series[series.key] || colors.text;
      ctx.beginPath();
      ctx.arc(x, y, 3, 0, Math.PI * 2);
      ctx.fill();
      ctx.strokeStyle = colors.surface;
      ctx.lineWidth = 1.2;
      ctx.stroke();
    });
    ctx.restore();
  }

  function updateChartOverlay(chart) {
    if (!chart.overlay) return;
    var visible = chart.series.filter(function (series) {
      return chart.visible.has(series.key);
    });
    if (!visible.length) {
      chart.overlay.textContent = 'All series hidden. Use the legend to restore a trace.';
      chart.overlay.hidden = false;
      return;
    }
    var withData = visible.some(function (series) {
      return chart.hasData[series.key];
    });
    if (!withData) {
      chart.overlay.textContent = 'No samples reported for the visible series.';
      chart.overlay.hidden = false;
      return;
    }
    chart.overlay.hidden = true;
  }

  /* ------------------------------------------------------------------ */
  /* Top contributors                                                    */
  /* ------------------------------------------------------------------ */

  function renderTop() {
    var tabsHost = $('top-tabs');
    var panelsHost = $('top-panels');
    if (!tabsHost || !panelsHost) return;
    clear(tabsHost);
    clear(panelsHost);
    var top = def(state.data, 'top', null);
    if (!top || typeof top !== 'object' || Array.isArray(top)) {
      panelsHost.appendChild(unavailableState('Rankings unavailable', 'The embedded report does not contain top-contributor rankings.'));
      setAside($('top-count'), null, 'rankings');
      return;
    }
    var metrics = [
      { key: 'cpu', label: 'CPU', caption: 'Top entities by CPU use' },
      { key: 'memory', label: 'Memory', caption: 'Top entities by memory use' },
      { key: 'io', label: 'I/O', caption: 'Top entities by disk I/O' },
      { key: 'network', label: 'Network', caption: 'Top entities by network traffic' }
    ];
    var available = 0;
    var tabs = [];
    var panels = [];
    metrics.forEach(function (metric, index) {
      var raw = def(top, metric.key, null);
      if (Array.isArray(raw)) available += 1;
      var tab = el('button', 'subtab' + (index === 0 ? ' is-active' : ''));
      tab.type = 'button';
      tab.id = 'top-tab-' + metric.key;
      tab.setAttribute('role', 'tab');
      tab.setAttribute('aria-selected', index === 0 ? 'true' : 'false');
      tab.setAttribute('aria-controls', 'top-panel-' + metric.key);
      tab.tabIndex = index === 0 ? 0 : -1;
      tab.setAttribute('data-metric', metric.key);
      tab.appendChild(el('span', '', metric.label));
      if (Array.isArray(raw)) tab.appendChild(el('span', 'subtab-count', fmtCount(raw.length)));
      tabs.push(tab);
      tabsHost.appendChild(tab);

      var panel = el('div', 'subpanel');
      panel.id = 'top-panel-' + metric.key;
      panel.setAttribute('role', 'tabpanel');
      panel.setAttribute('aria-labelledby', 'top-tab-' + metric.key);
      panel.tabIndex = 0;
      panel.hidden = index !== 0;
      if (!Array.isArray(raw)) {
        panel.appendChild(unavailableState(metric.label + ' ranking unavailable', 'No ' + metric.label.toLowerCase() + ' ranking array was embedded.'));
      } else if (raw.length === 0) {
        panel.appendChild(makeEmpty('No ' + metric.label + ' contributors', 'No entities were ranked for this metric in the report window. This is an empty ranking, not a zero measurement.'));
      } else {
        panel.appendChild(renderTopTable(metric, raw));
      }
      panels.push(panel);
      panelsHost.appendChild(panel);
    });
    setAside($('top-count'), fmtCount(available), 'available rankings');
    wireSubtabs(tabs, panels);
  }

  function wireSubtabs(tabs, panels) {
    function activate(index, focus) {
      tabs.forEach(function (tab, i) {
        var active = i === index;
        tab.classList.toggle('is-active', active);
        tab.setAttribute('aria-selected', active ? 'true' : 'false');
        tab.tabIndex = active ? 0 : -1;
        panels[i].hidden = !active;
      });
      if (focus && tabs[index]) tabs[index].focus();
    }
    tabs.forEach(function (tab, index) {
      tab.addEventListener('click', function () {
        state.topTab = tab.getAttribute('data-metric');
        activate(index, false);
      });
      tab.addEventListener('keydown', function (event) {
        var next = index;
        if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
        else if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
        else if (event.key === 'Home') next = 0;
        else if (event.key === 'End') next = tabs.length - 1;
        else return;
        event.preventDefault();
        activate(next, true);
        state.topTab = tabs[next].getAttribute('data-metric');
      });
    });
  }

  function renderTopTable(metric, rows) {
    var columns = [
      { label: '#', cls: 'num' },
      { label: 'Entity' },
      { label: 'Kind' },
      { label: 'Tool / container' },
      { label: 'CPU avg / max', cls: 'num' },
      { label: 'Memory max', cls: 'num' },
      { label: 'I/O read / write', cls: 'num' },
      { label: 'Net RX / TX', cls: 'num' },
      { label: 'Share', cls: 'num', title: 'Share of listed entities for this metric' }
    ];
    var table = buildTable(columns, metric.caption);
    var tbody = table.tbody;
    var listed = rows.slice(0, TOP_CAP);
    listed.forEach(function (entity, index) {
      if (!entity || typeof entity !== 'object') return;
      var row = el('tr');
      tableCell(row, pad2(index + 1), 'num');
      var name = nonEmptyString(def(entity, 'name', null)) ||
        nonEmptyString(def(entity, 'entity_id', null)) || 'Unidentified entity';
      var id = strOrNull(def(entity, 'entity_id', null));
      var role = nonEmptyString(def(entity, 'role', null));
      var entityCell = el('td', 'entity-cell');
      entityCell.appendChild(el('span', 'entity-name', name));
      if (id !== null && id !== name) entityCell.appendChild(el('span', 'entity-id', id));
      if (role) entityCell.appendChild(el('span', 'entity-id', 'role \u00b7 ' + role));
      row.appendChild(entityCell);
      var kind = nonEmptyString(def(entity, 'kind', null));
      tableCell(row, kind === null ? dashSpan() : makeChip(kind, 'tone-neutral'), 'kind-cell');
      var toolCell = el('td');
      var tool = nonEmptyString(def(entity, 'tool', null));
      var container = nonEmptyString(def(entity, 'container', null));
      if (tool) toolCell.appendChild(makeChip('tool \u00b7 ' + tool, 'tone-accent'));
      if (container) {
        if (tool) toolCell.appendChild(document.createTextNode(' '));
        toolCell.appendChild(makeChip('container \u00b7 ' + container, 'tone-info'));
      }
      if (!tool && !container) toolCell.appendChild(dashSpan());
      row.appendChild(toolCell);
      var cpuAvg = numOrNull(def(entity, 'cpu_avg_pct', null));
      var cpuMax = numOrNull(def(entity, 'cpu_max_pct', null));
      stackCell(row, [
        { label: 'avg', value: fmtPct(cpuAvg) },
        { label: 'max', value: fmtPct(cpuMax) }
      ], 'num');
      valueCell(row, fmtBytes(numOrNull(def(entity, 'memory_max_bytes', null))), 'num');
      stackCell(row, [
        { label: 'rd', value: fmtBytes(numOrNull(def(entity, 'io_read_bytes', null))) },
        { label: 'wr', value: fmtBytes(numOrNull(def(entity, 'io_write_bytes', null))) }
      ], 'num');
      stackCell(row, [
        { label: 'rx', value: fmtBytes(numOrNull(def(entity, 'net_rx_bytes', null))) },
        { label: 'tx', value: fmtBytes(numOrNull(def(entity, 'net_tx_bytes', null))) }
      ], 'num');
      var share = usageShare(metric.key, entity, listed);
      valueCell(row, share === null ? null : fmtPct(share), 'num');
      tbody.appendChild(row);
    });
    var wrapper = el('div', 'table-scroll');
    wrapper.appendChild(table.table);
    if (rows.length > TOP_CAP) {
      wrapper.appendChild(el('p', 'render-note', 'Showing top ' + fmtCount(TOP_CAP) + ' of ' + fmtCount(rows.length) + ' entities.'));
    }
    return wrapper;
  }

  function usageNumerator(metric, entity) {
    if (metric === 'cpu') return numOrNull(def(entity, 'cpu_avg_pct', null));
    if (metric === 'memory') return numOrNull(def(entity, 'memory_max_bytes', null));
    if (metric === 'io') {
      var read = numOrNull(def(entity, 'io_read_bytes', null));
      var write = numOrNull(def(entity, 'io_write_bytes', null));
      return read === null || write === null ? null : read + write;
    }
    var rx = numOrNull(def(entity, 'net_rx_bytes', null));
    var tx = numOrNull(def(entity, 'net_tx_bytes', null));
    return rx === null || tx === null ? null : rx + tx;
  }

  function usageShare(metric, entity, rows) {
    var numerator = usageNumerator(metric, entity);
    if (numerator === null) return null;
    var total = 0;
    rows.forEach(function (row) {
      if (!row || typeof row !== 'object') return;
      var value = usageNumerator(metric, row);
      if (value !== null && value > 0) total += value;
    });
    if (!(total > 0)) return null;
    return (numerator / total) * 100;
  }

  /* ------------------------------------------------------------------ */
  /* Process tree                                                        */
  /* ------------------------------------------------------------------ */

  function initProcesses() {
    state.processLastQuery = '';
    var processData = def(state.data, 'processes', null);
    var nodesRaw = processData && typeof processData === 'object' ? def(processData, 'nodes', null) : null;
    if (!processData || typeof processData !== 'object' || !Array.isArray(nodesRaw)) {
      setAside($('process-count'), null, 'processes');
      var unavailableView = $('process-view');
      if (unavailableView) {
        clear(unavailableView);
        unavailableView.appendChild(unavailableState('Process data unavailable', 'No process node array was embedded. This is unavailable data, not evidence that no processes existed.'));
      }
      setProcessNote('');
      disableProcessControls();
      return;
    }
    var seen = new Set();
    var nodes = [];
    nodesRaw.forEach(function (raw) {
      if (!raw || typeof raw !== 'object') return;
      var id = strOrNull(def(raw, 'id', null));
      if (id === null || id === '') return;
      if (seen.has(id)) return;
      seen.add(id);
      nodes.push({
        id: id,
        parent_id: strOrNull(def(raw, 'parent_id', null)),
        pid: numOrNull(def(raw, 'pid', null)),
        comm: nonEmptyString(def(raw, 'comm', null)) || 'process',
        executable: nonEmptyString(def(raw, 'executable', null)),
        tool: nonEmptyString(def(raw, 'tool', null)),
        role: nonEmptyString(def(raw, 'role', null)),
        unit: nonEmptyString(def(raw, 'unit', null)),
        container: nonEmptyString(def(raw, 'container', null)),
        session: nonEmptyString(def(raw, 'session', null)),
        start: numOrNull(def(raw, 'start', null)),
        end: numOrNull(def(raw, 'end', null)),
        end_reason: nonEmptyString(def(raw, 'end_reason', null))
      });
    });

    state.processNodes = nodes;
    state.processTotal = numOrNull(def(processData, 'total', null));
    if (state.processTotal === null) state.processTotal = nodes.length;
    state.processByParent = new Map();
    state.processChildren = new Map();
    state.processExpanded = new Set();
    state.processInitialized = false;
    state.processFlat = false;
    state.processRendered = 0;
    state.processIncluded = 0;
    state.processMatches = 0;

    setAside($('process-count'), fmtCount(nodes.length), 'embedded processes', state.processTotal > nodes.length ? fmtCount(state.processTotal) + ' observed total' : null);

    if (nodes.length === 0) {
      var view = $('process-view');
      if (view) view.appendChild(makeEmpty('No processes recorded', 'The process array is empty. No process sightings were embedded for this window.'));
      disableProcessControls();
      return;
    }

    var indexById = new Map();
    nodes.forEach(function (node) { indexById.set(node.id, node); });
    var validParents = 0;
    nodes.forEach(function (node) {
      if (node.parent_id !== null && node.parent_id !== node.id && indexById.has(node.parent_id)) {
        validParents += 1;
        if (!state.processChildren.has(node.parent_id)) state.processChildren.set(node.parent_id, []);
        state.processChildren.get(node.parent_id).push(node);
        state.processByParent.set(node.id, node.parent_id);
      } else {
        state.processByParent.set(node.id, null);
      }
    });
    state.processFlat = validParents === 0;
    state.processIndexById = indexById;
    state.processChildren.forEach(function (list) {
      list.sort(compareNodes);
    });

    setupProcessControls();
    if (state.processFlat) {
      var expandButton = $('process-expand');
      var collapseButton = $('process-collapse');
      if (expandButton) {
        expandButton.disabled = true;
        expandButton.title = 'Tree controls are unavailable when parent links are missing';
      }
      if (collapseButton) {
        collapseButton.disabled = true;
        collapseButton.title = 'Tree controls are unavailable when parent links are missing';
      }
    }
    renderProcessView();
  }

  function compareNodes(a, b) {
    if (a.start === null && b.start === null) return a.comm.localeCompare(b.comm);
    if (a.start === null) return 1;
    if (b.start === null) return -1;
    return a.start - b.start;
  }

  function disableProcessControls() {
    var search = $('process-search');
    var expand = $('process-expand');
    var collapse = $('process-collapse');
    if (search) search.disabled = true;
    if (expand) expand.disabled = true;
    if (collapse) collapse.disabled = true;
  }

  function setupProcessControls() {
    var search = $('process-search');
    var expand = $('process-expand');
    var collapse = $('process-collapse');
    if (search) {
      search.disabled = false;
      search.addEventListener('input', function () {
        window.clearTimeout(state.processTimer);
        state.processTimer = window.setTimeout(function () {
          state.processQuery = search.value || '';
          renderProcessView();
        }, 120);
      });
    }
    if (expand) {
      expand.disabled = false;
      expand.addEventListener('click', function () {
        expandProcessAll();
      });
    }
    if (collapse) {
      collapse.disabled = false;
      collapse.addEventListener('click', function () {
        state.processExpanded.clear();
        renderProcessView();
      });
    }
  }

  function nodeMatches(node, query) {
    if (!query) return true;
    var haystack = [
      node.comm,
      node.executable,
      node.tool,
      node.role,
      node.unit,
      node.container,
      node.session,
      node.end_reason,
      node.pid === null ? '' : String(node.pid),
      node.id
    ];
    for (var i = 0; i < haystack.length; i += 1) {
      var value = haystack[i];
      if (value && String(value).toLowerCase().indexOf(query) !== -1) return true;
    }
    return false;
  }

  function filteredProcessSet(query) {
    var nodes = state.processNodes;
    if (!query) return { nodes: nodes, matches: nodes.length, include: null };
    var include = new Set();
    var matches = 0;
    nodes.forEach(function (node) {
      if (!nodeMatches(node, query)) return;
      matches += 1;
      include.add(node.id);
      var current = node;
      var guard = 0;
      while (current && current.parent_id !== null && guard < 1000) {
        var parent = state.processIndexById ? state.processIndexById.get(current.parent_id) : null;
        if (!parent || include.has(parent.id)) break;
        include.add(parent.id);
        current = parent;
        guard += 1;
      }
    });
    return { nodes: nodes.filter(function (node) { return include.has(node.id); }), matches: matches, include: include };
  }

  function renderProcessView() {
    var view = $('process-view');
    if (!view) return;
    clear(view);
    if (!state.processNodes.length) return;
    var query = state.processQuery.trim().toLowerCase();
    var filtered = filteredProcessSet(query);
    state.processIncluded = filtered.nodes.length;
    state.processMatches = filtered.matches;

    if (state.processFlat) {
      view.appendChild(el('p', 'flat-note', 'Parent links were not reported; showing a flat process list instead of a tree.'));
      renderFlatProcesses(filtered.nodes, filtered.matches, query);
      return;
    }

    var roots = filtered.nodes.filter(function (node) {
      return !state.processByParent.get(node.id);
    });
    roots.sort(compareNodes);
    var included = new Set(filtered.nodes.map(function (node) { return node.id; }));
    var children = new Map();
    filtered.nodes.forEach(function (node) {
      var parentId = state.processByParent.get(node.id);
      if (!parentId || !included.has(parentId)) return;
      if (!children.has(parentId)) children.set(parentId, []);
      children.get(parentId).push(node);
    });
    children.forEach(function (list) { list.sort(compareNodes); });

    if (!state.processInitialized) {
      state.processInitialized = true;
      roots.forEach(function (root) {
        if (children.has(root.id)) state.processExpanded.add(root.id);
      });
    }
    if (query && state.processLastQuery !== query) {
      filtered.nodes.forEach(function (node) {
        if (children.has(node.id)) state.processExpanded.add(node.id);
      });
    }
    if (!query) state.processLastQuery = '';
    if (query) state.processLastQuery = query;

    if (!filtered.nodes.length) {
      setProcessNote('No process nodes match "' + state.processQuery.trim() + '". Clear the filter to restore the tree.');
      view.appendChild(makeEmpty('No matching processes', 'No embedded process node matches the current search. This is an empty filter result, not evidence that no processes existed.'));
      return;
    }

    var tree = el('div', 'tree');
    var list = el('ul', 'tree-list');
    var visited = new Set();
    var rendered = { count: 0 };

    function renderNode(node, depth, parentList) {
      if (rendered.count >= TREE_CAP || visited.has(node.id)) return;
      visited.add(node.id);
      rendered.count += 1;
      var childNodes = children.get(node.id) || [];
      var expanded = state.processExpanded.has(node.id);
      var li = el('li', 'tree-item');
      var row = el('div', 'tree-row');
      var hasChildren = childNodes.length > 0;
      var toggle;
      if (hasChildren) {
        toggle = el('button', 'tree-toggle');
        toggle.type = 'button';
        toggle.setAttribute('aria-expanded', expanded ? 'true' : 'false');
        toggle.setAttribute('aria-label', (expanded ? 'Collapse' : 'Expand') + ' children of ' + node.comm + (node.pid === null ? '' : ' ' + node.pid));
        toggle.title = (expanded ? 'Collapse' : 'Expand') + ' ' + childNodes.length + ' child node' + (childNodes.length === 1 ? '' : 's');
      } else {
        toggle = el('span', 'tree-leaf');
        toggle.setAttribute('aria-hidden', 'true');
      }
      row.appendChild(toggle);

      var main = el('div', 'tree-main');
      var nameLine = el('div', 'tree-name');
      nameLine.appendChild(el('span', '', node.comm));
      if (node.pid !== null) nameLine.appendChild(el('span', 'tree-pid', 'PID ' + node.pid));
      if (hasChildren) nameLine.appendChild(el('span', 'child-count', childNodes.length + ' child' + (childNodes.length === 1 ? '' : 'ren')));
      main.appendChild(nameLine);
      if (node.executable) {
        var exec = el('span', 'tree-exec', node.executable);
        exec.title = node.executable;
        main.appendChild(exec);
      }
      var badges = el('div', 'tree-badges');
      appendNodeBadges(badges, node);
      if (badges.childNodes.length) main.appendChild(badges);
      row.appendChild(main);

      var life = el('div', 'tree-life');
      var times = el('span', 'tree-times');
      times.appendChild(document.createTextNode(fmtShortStamp(node.start) === null ? DASH : fmtShortStamp(node.start)));
      times.appendChild(document.createTextNode(' \u2192 '));
      times.appendChild(document.createTextNode(node.end === null ? 'end not observed' : (fmtShortStamp(node.end) === null ? DASH : fmtShortStamp(node.end))));
      life.appendChild(times);
      var duration = durationBetween(node.start, node.end);
      if (duration !== null) life.appendChild(el('span', 'tree-duration', duration));
      if (node.end_reason) {
        var endLine = el('span', 'tree-end');
        endLine.appendChild(el('span', 'tree-end-reason', 'end reason: ' + node.end_reason));
        life.appendChild(endLine);
      }
      row.appendChild(life);
      li.appendChild(row);

      var childList = el('ul', 'tree-list');
      childList.hidden = !expanded;
      for (var i = 0; i < childNodes.length; i += 1) {
        renderNode(childNodes[i], depth + 1, childList);
      }
      if (hasChildren) {
        toggle.addEventListener('click', function () {
          var isExpanded = state.processExpanded.has(node.id);
          if (isExpanded) state.processExpanded.delete(node.id);
          else state.processExpanded.add(node.id);
          childList.hidden = isExpanded;
          toggle.setAttribute('aria-expanded', isExpanded ? 'false' : 'true');
          toggle.setAttribute('aria-label', (isExpanded ? 'Expand' : 'Collapse') + ' children of ' + node.comm + (node.pid === null ? '' : ' ' + node.pid));
        });
        li.appendChild(childList);
      }
      parentList.appendChild(li);
    }

    roots.forEach(function (root) {
      renderNode(root, 0, list);
    });
    if (rendered.count < TREE_CAP) {
      filtered.nodes.forEach(function (node) {
        if (!visited.has(node.id) && rendered.count < TREE_CAP) renderNode(node, 0, list);
      });
    }
    tree.appendChild(list);
    view.appendChild(tree);
    state.processRendered = rendered.count;

    var note = [];
    note.push('Showing ' + fmtCount(rendered.count) + ' of ' + fmtCount(state.processIncluded) + (query ? ' matching ' : ' ') + 'process nodes.');
    if (query) note.push('Filter "' + state.processQuery.trim() + '".');
    if (query) note.push(fmtCount(state.processMatches) + ' direct match' + (state.processMatches === 1 ? '' : 'es') + '.');
    if (state.processTotal > state.processNodes.length) {
      note.push('Embedded sample: ' + fmtCount(state.processNodes.length) + ' of ' + fmtCount(state.processTotal) + ' observed processes.');
    }
    if (state.processIncluded > rendered.count) note.push('Render cap ' + fmtCount(TREE_CAP) + '.');
    setProcessNote(note.join(' '));
  }

  function appendNodeBadges(parent, node) {
    if (node.tool) parent.appendChild(makeChip('tool \u00b7 ' + node.tool, 'tone-accent'));
    if (node.role) parent.appendChild(makeChip('role \u00b7 ' + node.role, 'tone-neutral'));
    if (node.unit) parent.appendChild(makeChip('unit \u00b7 ' + node.unit, 'tone-info'));
    if (node.container) parent.appendChild(makeChip('container \u00b7 ' + node.container, 'tone-warn'));
    if (node.session) parent.appendChild(makeChip('session \u00b7 ' + node.session, 'tone-neutral'));
  }

  function setProcessNote(text) {
    var note = $('process-note');
    if (note) note.textContent = text;
  }

  function expandProcessAll() {
    if (!state.processNodes.length) return;
    var query = state.processQuery.trim().toLowerCase();
    var filtered = filteredProcessSet(query);
    filtered.nodes.forEach(function (node) {
      if (state.processChildren.has(node.id) || (state.processFlat === false && hasIncludedChildren(node))) {
        state.processExpanded.add(node.id);
      }
    });
    // Every node that is a parent in the included set should be expanded.
    var included = new Set(filtered.nodes.map(function (node) { return node.id; }));
    filtered.nodes.forEach(function (node) {
      var parentId = state.processByParent.get(node.id);
      if (parentId && included.has(parentId)) state.processExpanded.add(parentId);
    });
    renderProcessView();
  }

  function hasIncludedChildren(node) {
    var list = state.processChildren.get(node.id);
    if (!list || !list.length) return false;
    var query = state.processQuery.trim().toLowerCase();
    if (!query) return true;
    return list.some(function (child) { return nodeMatches(child, query); });
  }

  function renderFlatProcesses(nodes, matches, query) {
    var view = $('process-view');
    if (!view) return;
    if (!nodes.length) {
      setProcessNote('No process nodes match "' + state.processQuery.trim() + '". Clear the filter to restore the flat list.');
      view.appendChild(makeEmpty('No matching processes', 'No embedded process node matches the current search. This is an empty filter result, not evidence that no processes existed.'));
      return;
    }
    var columns = [
      { label: 'PID', cls: 'num' },
      { label: 'Process' },
      { label: 'Tool / unit' },
      { label: 'Container / session' },
      { label: 'Lifetime' },
      { label: 'End reason' }
    ];
    var table = buildTable(columns, 'Flat process list');
    nodes.slice(0, TREE_CAP).forEach(function (node) {
      var row = el('tr');
      valueCell(row, fmtCount(node.pid), 'num');
      var processCell = el('td');
      processCell.appendChild(el('span', 'entity-name', node.comm));
      if (node.executable) processCell.appendChild(el('span', 'entity-id', node.executable));
      row.appendChild(processCell);
      var toolCell = el('td');
      if (node.tool) toolCell.appendChild(makeChip('tool \u00b7 ' + node.tool, 'tone-accent'));
      if (node.unit) {
        if (node.tool) toolCell.appendChild(document.createTextNode(' '));
        toolCell.appendChild(makeChip('unit \u00b7 ' + node.unit, 'tone-info'));
      }
      if (!node.tool && !node.unit) toolCell.appendChild(dashSpan());
      row.appendChild(toolCell);
      var contextCell = el('td');
      if (node.container) contextCell.appendChild(makeChip('container \u00b7 ' + node.container, 'tone-warn'));
      if (node.session) {
        if (node.container) contextCell.appendChild(document.createTextNode(' '));
        contextCell.appendChild(makeChip('session \u00b7 ' + node.session, 'tone-neutral'));
      }
      if (!node.container && !node.session) contextCell.appendChild(dashSpan());
      row.appendChild(contextCell);
      var life = el('td');
      var times = el('div', 'cell-stack');
      times.appendChild(el('span', '', (fmtShortStamp(node.start) === null ? DASH : fmtShortStamp(node.start)) + ' \u2192 ' + (node.end === null ? 'end not observed' : (fmtShortStamp(node.end) === null ? DASH : fmtShortStamp(node.end)))));
      var duration = durationBetween(node.start, node.end);
      if (duration !== null) times.appendChild(el('span', '', duration));
      life.appendChild(times);
      row.appendChild(life);
      var endCell = el('td');
      if (node.end_reason) endCell.appendChild(makeChip(node.end_reason, 'tone-warn'));
      else endCell.appendChild(dashSpan());
      row.appendChild(endCell);
      table.tbody.appendChild(row);
    });
    var wrap = el('div', 'table-scroll');
    wrap.appendChild(table.table);
    view.appendChild(wrap);
    var shown = Math.min(nodes.length, TREE_CAP);
    var note = 'Showing ' + fmtCount(shown) + ' of ' + fmtCount(state.processIncluded) + (query ? ' matching ' : ' ') + 'process nodes in a flat list (parent links unavailable).';
    if (query) note += ' Filter "' + state.processQuery.trim() + '". ' + fmtCount(matches) + ' direct matches.';
    if (state.processTotal > state.processNodes.length) note += ' Embedded sample: ' + fmtCount(state.processNodes.length) + ' of ' + fmtCount(state.processTotal) + ' observed processes.';
    setProcessNote(note);
    state.processRendered = shown;
  }

  /* ------------------------------------------------------------------ */
  /* Incidents                                                           */
  /* ------------------------------------------------------------------ */

  function renderIncidents() {
    var wrap = $('incidents-table-wrap');
    if (!wrap) return;
    clear(wrap);
    var raw = def(state.data, 'incidents', null);
    if (!Array.isArray(raw)) {
      wrap.appendChild(unavailableState('Incident data unavailable', 'No incident array was embedded. This is unavailable data, not evidence that no incidents occurred.'));
      setAside($('incidents-count'), null, 'incidents');
      setTabCount('tab-count-incidents', null);
      return;
    }
    var incidents = raw.filter(function (incident) {
      return incident && typeof incident === 'object';
    });
    setAside($('incidents-count'), fmtCount(incidents.length), 'incidents',
      incidents.length > INCIDENT_CAP ? 'showing ' + fmtCount(INCIDENT_CAP) : null);
    setTabCount('tab-count-incidents', incidents.length);
    if (incidents.length === 0) {
      wrap.appendChild(makeEmpty('No incidents recorded', 'The incident register is empty for this report window. This is a recorded empty register, not proof that no anomaly occurred.'));
      return;
    }
    var columns = [
      { label: 'ID', cls: 'num' },
      { label: 'Time range' },
      { label: 'Entity' },
      { label: 'Metric' },
      { label: 'Reason' },
      { label: 'Peak', cls: 'num' },
      { label: 'Baseline', cls: 'num' },
      { label: 'Flags' },
      { label: 'Logs', cls: 'row-action' }
    ];
    var table = buildTable(columns, 'Incident register');
    incidents.slice(0, INCIDENT_CAP).forEach(function (incident, index) {
      var row = el('tr', 'incident-row');
      row.setAttribute('data-incident-index', String(index));
      row.title = 'Show logs correlated with this incident';
      valueCell(row, fmtCount(def(incident, 'id', null)), 'num');
      var start = numOrNull(def(incident, 'start', null));
      var end = numOrNull(def(incident, 'end', null));
      var timeCell = el('td', 'incident-time');
      timeCell.appendChild(document.createTextNode(fmtStamp(start) === null ? DASH : fmtStamp(start)));
      timeCell.appendChild(document.createTextNode(' \u2192 '));
      timeCell.appendChild(document.createTextNode(end === null ? 'open' : (fmtStamp(end) === null ? DASH : fmtStamp(end))));
      row.appendChild(timeCell);
      row.appendChild(incidentEntityCell(def(incident, 'entity_id', null)));
      var metric = strOrNull(def(incident, 'metric', null));
      var metricCell = el('td');
      metricCell.appendChild(el('span', 'cell-strong', metricLabel(metric)));
      if (metric) metricCell.appendChild(el('span', 'cell-sub', metric));
      row.appendChild(metricCell);
      tableCell(row, nonEmptyString(def(incident, 'reason', null)) === null ? dashSpan() : el('span', '', nonEmptyString(def(incident, 'reason', null))));
      valueCell(row, formatMetricValue(metric, numOrNull(def(incident, 'peak', null))), 'num');
      valueCell(row, formatMetricValue(metric, numOrNull(def(incident, 'baseline', null))), 'num');
      var flags = el('div', 'flag-list');
      if (def(incident, 'acknowledged', false) === true) flags.appendChild(makeChip('acknowledged', 'tone-neutral'));
      if (def(incident, 'evidence_loss', false) === true) flags.appendChild(makeChip('evidence loss', 'tone-danger'));
      if (!flags.childNodes.length) flags.appendChild(dashSpan());
      row.appendChild(flags);
      var actionCell = el('td', 'row-action');
      var button = el('button', 'button button-quiet', 'Show logs');
      button.type = 'button';
      button.addEventListener('click', function (event) {
        event.stopPropagation();
        filterLogsForIncident(incident);
      });
      actionCell.appendChild(button);
      row.appendChild(actionCell);
      row.addEventListener('click', function (event) {
        if (event.target && event.target.closest && event.target.closest('button, a, input, select')) return;
        filterLogsForIncident(incident);
      });
      table.tbody.appendChild(row);
    });
    wrap.appendChild(table.table);
  }

  function incidentEntityCell(entityId) {
    var cell = el('td');
    var id = strOrNull(entityId);
    if (id === null || id === '') {
      cell.appendChild(dashSpan());
      return cell;
    }
    var name = state.entityNames.get(id) || null;
    if (name) {
      cell.appendChild(el('span', 'entity-name', name));
      cell.appendChild(el('span', 'entity-id', id));
    } else {
      cell.appendChild(el('span', 'entity-name', id));
    }
    return cell;
  }

  function filterLogsForIncident(incident) {
    // Clear text/level/source filters so the incident correlation is visible.
    state.logFilters = { query: '', level: 'all', source: 'all' };
    var search = $('log-search');
    var levelSelect = $('log-level');
    var sourceSelect = $('log-source');
    if (search) search.value = '';
    if (levelSelect) levelSelect.value = 'all';
    if (sourceSelect) sourceSelect.value = 'all';
    var entityId = strOrNull(def(incident, 'entity_id', null));
    var start = numOrNull(def(incident, 'start', null));
    var end = numOrNull(def(incident, 'end', null));
    if (end === null) end = toTimestamp(def(state.meta, 'until', null));
    state.incidentFilter = {
      id: numOrNull(def(incident, 'id', null)),
      entity_id: entityId,
      start: start,
      end: end
    };
    renderLogContext();
    renderLogs();
    activateView('logs', { updateHash: true });
    window.requestAnimationFrame(function () {
      var context = $('log-context');
      if (context && !context.hidden) {
        try {
          context.scrollIntoView({ behavior: 'auto', block: 'center' });
        } catch (error) {
          context.scrollIntoView();
        }
        try {
          context.focus({ preventScroll: true });
        } catch (error) {
          context.focus();
        }
      }
    });
  }

  /* ------------------------------------------------------------------ */
  /* Logs & events                                                       */
  /* ------------------------------------------------------------------ */

  function initLogs() {
    var raw = def(state.data, 'logs', null);
    state.logs = Array.isArray(raw) ? raw : [];
    var levelSelect = $('log-level');
    var sourceSelect = $('log-source');
    var search = $('log-search');
    var reset = $('log-reset');

    if (levelSelect) {
      clear(levelSelect);
      levelSelect.appendChild(option('all', 'All levels'));
      uniqueLogValues('level').forEach(function (level) {
        levelSelect.appendChild(option(level, level));
      });
    }
    if (sourceSelect) {
      clear(sourceSelect);
      sourceSelect.appendChild(option('all', 'All sources'));
      uniqueLogValues('source_id').forEach(function (source) {
        sourceSelect.appendChild(option(source, source));
      });
    }

    if (search) {
      search.disabled = !Array.isArray(raw);
      search.addEventListener('input', function () {
        window.clearTimeout(state.logTimer);
        state.logTimer = window.setTimeout(function () {
          state.logFilters.query = search.value || '';
          renderLogs();
        }, 120);
      });
    }
    if (levelSelect) {
      levelSelect.disabled = !Array.isArray(raw);
      levelSelect.addEventListener('change', function () {
        state.logFilters.level = levelSelect.value;
        renderLogs();
      });
    }
    if (sourceSelect) {
      sourceSelect.disabled = !Array.isArray(raw);
      sourceSelect.addEventListener('change', function () {
        state.logFilters.source = sourceSelect.value;
        renderLogs();
      });
    }
    if (reset) {
      reset.addEventListener('click', function () {
        state.logFilters = { query: '', level: 'all', source: 'all' };
        state.incidentFilter = null;
        if (search) search.value = '';
        if (levelSelect) levelSelect.value = 'all';
        if (sourceSelect) sourceSelect.value = 'all';
        renderLogContext();
        renderLogs();
        if (search) search.focus();
      });
    }
    renderLogs();
    renderLogContext();
  }

  function option(value, label) {
    var item = document.createElement('option');
    item.value = value;
    item.textContent = label;
    return item;
  }

  function uniqueLogValues(key) {
    var values = new Set();
    state.logs.forEach(function (log) {
      if (!log || typeof log !== 'object') return;
      var value = nonEmptyString(def(log, key, null));
      if (value !== null) values.add(value);
    });
    return Array.from(values).sort(function (a, b) {
      return a.localeCompare(b);
    });
  }

  function currentLogs() {
    var raw = def(state.data, 'logs', null);
    return Array.isArray(raw) ? raw : null;
  }

  function renderLogs() {
    var wrap = $('log-table-wrap');
    var note = $('log-note');
    if (!wrap) return;
    clear(wrap);
    var logs = currentLogs();
    var summaryCount = numOrNull(def(state.summary, 'log_count', null));
    var eventCount = numOrNull(def(state.summary, 'event_count', null));
    setAside(
      $('logs-count'),
      summaryCount !== null ? fmtCount(summaryCount) : (logs === null ? null : fmtCount(logs.length)),
      'stored log entries',
      eventCount === null ? null : fmtCount(eventCount) + ' events'
    );

    if (logs === null) {
      wrap.appendChild(unavailableState('Log data unavailable', 'No log array was embedded. This is unavailable data, not evidence that no log lines existed.'));
      if (note) note.textContent = 'Embedded logs unavailable.';
      return;
    }

    var query = state.logFilters.query.trim().toLowerCase();
    var filtered = logs.filter(function (log) {
      if (!log || typeof log !== 'object') return false;
      var level = nonEmptyString(def(log, 'level', null));
      if (state.logFilters.level !== 'all' && level !== state.logFilters.level) return false;
      var source = nonEmptyString(def(log, 'source_id', null));
      if (state.logFilters.source !== 'all' && source !== state.logFilters.source) return false;
      if (state.incidentFilter) {
        var incident = state.incidentFilter;
        if (incident.entity_id !== null) {
          var entity = strOrNull(def(log, 'entity_id', null));
          if (entity !== incident.entity_id) return false;
        }
        var wall = numOrNull(def(log, 'wall', null));
        if (incident.start !== null && (wall === null || wall < incident.start)) return false;
        if (incident.end !== null && (wall === null || wall > incident.end)) return false;
      }
      if (query) {
        var haystack = [
          nonEmptyString(def(log, 'message', null)) || '',
          nonEmptyString(def(log, 'source_id', null)) || '',
          nonEmptyString(def(log, 'entity_id', null)) || '',
          nonEmptyString(def(log, 'level', null)) || ''
        ].join(' ').toLowerCase();
        if (haystack.indexOf(query) === -1) return false;
      }
      return true;
    });

    var displayed = filtered.slice(0, LOG_CAP);
    var table = buildTable([
      { label: 'Time' },
      { label: 'Level' },
      { label: 'Source' },
      { label: 'Entity' },
      { label: 'Message' }
    ], 'Filtered log entries');
    displayed.forEach(function (log) {
      var row = el('tr');
      var time = fmtStamp(def(log, 'wall', null));
      tableCell(row, time === null ? dashSpan() : el('span', 'cell-strong', time));
      var level = nonEmptyString(def(log, 'level', null));
      var levelCell = el('td');
      levelCell.appendChild(level === null ? dashSpan() : makeChip(level, levelTone(level)));
      row.appendChild(levelCell);
      var source = nonEmptyString(def(log, 'source_id', null));
      var sourceCell = el('td');
      sourceCell.appendChild(source === null ? dashSpan() : el('span', 'entity-name', source));
      row.appendChild(sourceCell);
      var entity = nonEmptyString(def(log, 'entity_id', null));
      var entityCell = el('td');
      entityCell.appendChild(entity === null ? dashSpan() : el('span', 'entity-ref', entity));
      row.appendChild(entityCell);
      var messageCell = el('td');
      var message = strOrNull(def(log, 'message', null));
      var code = el('code', 'log-message' + (message === '' || message === null ? ' is-empty' : ''), message === '' || message === null ? '(empty message)' : message);
      messageCell.appendChild(code);
      if (def(log, 'truncated', false) === true) {
        var flag = makeChip('truncated');
        flag.classList.add('truncated-flag');
        var flags = el('span', 'log-flags');
        flags.appendChild(flag);
        messageCell.appendChild(flags);
      }
      row.appendChild(messageCell);
      table.tbody.appendChild(row);
    });
    if (displayed.length > 0) {
      wrap.appendChild(table.table);
    } else {
      wrap.appendChild(makeEmpty('No matching logs', 'No embedded log entries match the current text, level, source and incident filters. Try clearing one filter; absence here does not mean the host was quiet.'));
    }

    var noteParts = [];
    noteParts.push('Showing first ' + fmtCount(displayed.length) + ' of ' + fmtCount(filtered.length) + ' matching log entries.');
    if (filtered.length > LOG_CAP) noteParts.push('Display cap ' + fmtCount(LOG_CAP) + '.');
    if (summaryCount !== null && summaryCount > logs.length) noteParts.push('Embedded sample: ' + fmtCount(logs.length) + ' of ' + fmtCount(summaryCount) + ' stored entries.');
    var filterLabels = [];
    if (state.logFilters.query.trim()) filterLabels.push('text "' + state.logFilters.query.trim() + '"');
    if (state.logFilters.level !== 'all') filterLabels.push('level ' + state.logFilters.level);
    if (state.logFilters.source !== 'all') filterLabels.push('source ' + state.logFilters.source);
    if (state.incidentFilter) filterLabels.push('incident ' + (state.incidentFilter.id === null ? 'filter' : '#' + state.incidentFilter.id));
    if (filterLabels.length) noteParts.push('Active filters: ' + filterLabels.join(', ') + '.');
    if (note) note.textContent = noteParts.join(' ');
  }

  function renderLogContext() {
    var banner = $('log-context');
    if (!banner) return;
    clear(banner);
    if (!state.incidentFilter) {
      banner.hidden = true;
      return;
    }
    var filter = state.incidentFilter;
    banner.hidden = false;
    banner.setAttribute('role', 'status');
    banner.setAttribute('tabindex', '-1');
    var text = el('span', 'context-text');
    text.appendChild(document.createTextNode('Incident filter \u00b7 '));
    text.appendChild(el('strong', '', filter.id === null ? 'unknown ID' : '#' + filter.id));
    if (filter.entity_id !== null) {
      text.appendChild(document.createTextNode(' \u00b7 entity '));
      text.appendChild(el('strong', '', filter.entity_id));
    }
    if (filter.start !== null) {
      text.appendChild(document.createTextNode(' \u00b7 ' + (fmtStamp(filter.start) || DASH) + ' \u2192 ' + (filter.end === null ? 'open' : (fmtStamp(filter.end) || DASH))));
    }
    text.appendChild(document.createTextNode(' \u00b7 matching logs only'));
    banner.appendChild(text);
    var clearButton = el('button', 'button button-quiet', 'Clear incident filter');
    clearButton.type = 'button';
    clearButton.addEventListener('click', function () {
      state.incidentFilter = null;
      renderLogContext();
      renderLogs();
      var search = $('log-search');
      if (search) search.focus();
    });
    banner.appendChild(clearButton);
  }

  function renderEvents() {
    var wrap = $('events-table-wrap');
    var note = $('events-note');
    if (!wrap) return;
    clear(wrap);
    var raw = def(state.data, 'events', null);
    if (!Array.isArray(raw)) {
      wrap.appendChild(unavailableState('Event data unavailable', 'No event array was embedded. This is unavailable data, not evidence that no events occurred.'));
      if (note) note.textContent = 'Embedded events unavailable.';
      return;
    }
    if (raw.length === 0) {
      wrap.appendChild(makeEmpty('No events recorded', 'The event stream is empty for this report window.'));
      if (note) note.textContent = '0 embedded events.';
      return;
    }
    var events = raw.filter(function (event) { return event && typeof event === 'object'; });
    var table = buildTable([
      { label: 'Time' },
      { label: 'Severity' },
      { label: 'Kind' },
      { label: 'Entity' },
      { label: 'Provenance' }
    ], 'Lifecycle and system events');
    events.slice(0, EVENT_CAP).forEach(function (event) {
      var row = el('tr');
      var time = fmtStamp(def(event, 'wall', null));
      tableCell(row, time === null ? dashSpan() : el('span', 'cell-strong', time));
      var severity = nonEmptyString(def(event, 'severity', null));
      var severityCell = el('td');
      severityCell.appendChild(severity === null ? dashSpan() : makeChip(severity, levelTone(severity)));
      row.appendChild(severityCell);
      tableCell(row, nonEmptyString(def(event, 'kind', null)) === null ? dashSpan() : el('span', '', nonEmptyString(def(event, 'kind', null))));
      var entity = nonEmptyString(def(event, 'entity_id', null));
      tableCell(row, entity === null ? dashSpan() : el('span', 'entity-ref', entity));
      var provenance = nonEmptyString(def(event, 'provenance', null));
      tableCell(row, provenance === null ? dashSpan() : el('span', 'cell-sub', provenance));
      table.tbody.appendChild(row);
    });
    var tableWrap = el('div', 'table-scroll');
    tableWrap.appendChild(table.table);
    wrap.appendChild(tableWrap);
    var noteParts = ['Showing ' + fmtCount(Math.min(events.length, EVENT_CAP)) + ' of ' + fmtCount(events.length) + ' embedded events.'];
    if (events.length > EVENT_CAP) noteParts.push('Display cap ' + fmtCount(EVENT_CAP) + '.');
    if (note) note.textContent = noteParts.join(' ');
  }

  /* ------------------------------------------------------------------ */
  /* Coverage                                                            */
  /* ------------------------------------------------------------------ */

  function renderCoverage() {
    var coverage = def(state.data, 'coverage', null);
    if (!coverage || typeof coverage !== 'object' || Array.isArray(coverage)) {
      var collectorsWrap = $('collectors-wrap');
      var gapsWrap = $('gaps-wrap');
      var integrationsWrap = $('integrations-wrap');
      if (collectorsWrap) {
        clear(collectorsWrap);
        collectorsWrap.appendChild(unavailableState('Collector data unavailable', 'No coverage ledger was embedded. Absence of reported loss is not proof of complete collection.'));
      }
      if (gapsWrap) {
        clear(gapsWrap);
        gapsWrap.appendChild(unavailableState('Gap data unavailable', 'No gap ledger was embedded. The absence of reported gaps is not evidence of complete coverage.'));
      }
      if (integrationsWrap) {
        clear(integrationsWrap);
        integrationsWrap.appendChild(unavailableState('Integration data unavailable', 'No integration ledger was embedded.'));
      }
      setAside($('coverage-count'), null, 'collectors');
      return;
    }
    var collectors = asArray(def(coverage, 'collectors', null), null);
    var gaps = asArray(def(coverage, 'gaps', null), null);
    var integrations = asArray(def(coverage, 'integrations', null), null);
    setAside($('coverage-count'), collectors === null ? null : fmtCount(collectors.length), 'collectors',
      gaps === null ? null : fmtCount(gaps.filter(function (gap) { return gap && typeof gap === 'object' && !isNum(def(gap, 'resolved', null)); }).length) + ' open gaps');
    renderCollectors(collectors);
    renderGaps(gaps);
    renderIntegrations(integrations);
    updateNavCoverage();
  }

  function renderCollectors(collectors) {
    var host = $('collectors-wrap');
    if (!host) return;
    clear(host);
    if (collectors === null) {
      host.appendChild(unavailableState('Collector data unavailable', 'The collector array was not embedded. This is unavailable, not zero loss.'));
      return;
    }
    if (collectors.length === 0) {
      host.appendChild(makeEmpty('No collectors reported', 'The collector ledger is empty. No collector health was recorded for this window.'));
      return;
    }
    var columns = [
      { label: 'Collector' },
      { label: 'Configured' },
      { label: 'Availability' },
      { label: 'Permission' },
      { label: 'Received', cls: 'num' },
      { label: 'Persisted', cls: 'num' },
      { label: 'Dropped', cls: 'num' },
      { label: 'Truncated', cls: 'num' },
      { label: 'Queue HWM', cls: 'num' },
      { label: 'Last success' },
      { label: 'Last error' }
    ];
    var table = buildTable(columns, 'Collector coverage and loss counters');
    collectors.slice(0, COLLECTOR_CAP).forEach(function (collector) {
      if (!collector || typeof collector !== 'object') return;
      var row = el('tr');
      var id = nonEmptyString(def(collector, 'id', null));
      tableCell(row, id === null ? dashSpan() : el('span', 'cell-strong', id));
      appendStatusCell(row, def(collector, 'configured', null));
      appendStatusCell(row, def(collector, 'availability', null));
      appendStatusCell(row, def(collector, 'permission', null));
      valueCell(row, fmtCount(numOrNull(def(collector, 'received', null))), 'num');
      valueCell(row, fmtCount(numOrNull(def(collector, 'persisted', null))), 'num');
      valueCell(row, fmtCount(numOrNull(def(collector, 'dropped', null))), 'num');
      valueCell(row, fmtCount(numOrNull(def(collector, 'truncated', null))), 'num');
      valueCell(row, fmtCount(numOrNull(def(collector, 'queue_high_water', null))), 'num');
      var success = fmtStamp(def(collector, 'last_success', null));
      tableCell(row, success === null ? dashSpan() : el('span', 'last-success', success));
      var error = nonEmptyString(def(collector, 'last_error', null));
      tableCell(row, error === null ? dashSpan() : el('span', 'error-text', error));
      table.tbody.appendChild(row);
    });
    var wrap = el('div', 'table-scroll');
    wrap.appendChild(table.table);
    host.appendChild(wrap);
    appendBoundedNote(host, Math.min(collectors.length, COLLECTOR_CAP), collectors.length, 'collectors');
  }

  function appendStatusCell(row, value) {
    var cell = el('td');
    cell.appendChild(statusChip(value));
    row.appendChild(cell);
  }

  function renderGaps(gaps) {
    var host = $('gaps-wrap');
    if (!host) return;
    clear(host);
    if (gaps === null) {
      host.appendChild(unavailableState('Gap data unavailable', 'The gap array was not embedded. Missing gap evidence is not proof of complete coverage.'));
      return;
    }
    if (gaps.length === 0) {
      host.appendChild(makeEmpty('No coverage gaps reported', 'The gap ledger is empty for this report window. This means no gaps were reported, not that coverage was complete.'));
      return;
    }
    var columns = [
      { label: 'Source' },
      { label: 'Kind' },
      { label: 'Detail' },
      { label: 'Since' },
      { label: 'Status' }
    ];
    var table = buildTable(columns, 'Coverage gaps');
    gaps.slice(0, GAP_CAP).forEach(function (gap) {
      if (!gap || typeof gap !== 'object') return;
      var row = el('tr');
      var source = nonEmptyString(def(gap, 'source_id', null));
      tableCell(row, source === null ? dashSpan() : el('span', 'cell-strong', source));
      var kind = nonEmptyString(def(gap, 'kind', null));
      tableCell(row, kind === null ? dashSpan() : makeChip(kind, 'tone-warn'));
      var detail = nonEmptyString(def(gap, 'detail', null));
      var detailCell = el('td');
      detailCell.appendChild(detail === null ? dashSpan() : el('span', '', detail));
      row.appendChild(detailCell);
      var since = fmtStamp(def(gap, 'since', null));
      tableCell(row, since === null ? dashSpan() : el('span', 'last-success', since));
      var resolved = numOrNull(def(gap, 'resolved', null));
      var statusCell = el('td');
      var flag = makeChip(resolved === null ? 'open' : 'resolved');
      flag.classList.add(resolved === null ? 'gap-open' : 'gap-resolved');
      statusCell.appendChild(flag);
      if (resolved !== null) {
        var resolvedText = fmtStamp(resolved);
        if (resolvedText) statusCell.appendChild(el('span', 'cell-sub', resolvedText));
      }
      row.appendChild(statusCell);
      table.tbody.appendChild(row);
    });
    var wrap = el('div', 'table-scroll');
    wrap.appendChild(table.table);
    host.appendChild(wrap);
    appendBoundedNote(host, Math.min(gaps.length, GAP_CAP), gaps.length, 'coverage gaps');
  }

  function renderIntegrations(integrations) {
    var host = $('integrations-wrap');
    if (!host) return;
    clear(host);
    if (integrations === null) {
      host.appendChild(unavailableState('Integration data unavailable', 'The integration array was not embedded.'));
      return;
    }
    if (integrations.length === 0) {
      host.appendChild(makeEmpty('No integrations reported', 'No optional enrichment integrations were configured or detected for this window. Baseline accounting is unaffected.'));
      return;
    }
    var columns = [
      { label: 'Integration' },
      { label: 'Configured' },
      { label: 'Detected' },
      { label: 'Version' },
      { label: 'Capabilities' },
      { label: 'Last error' }
    ];
    var table = buildTable(columns, 'Optional integrations');
    integrations.slice(0, INTEGRATION_CAP).forEach(function (integration) {
      if (!integration || typeof integration !== 'object') return;
      var row = el('tr');
      var id = nonEmptyString(def(integration, 'id', null));
      tableCell(row, id === null ? dashSpan() : el('span', 'cell-strong', id));
      appendStatusCell(row, def(integration, 'configured', null));
      appendStatusCell(row, def(integration, 'detected', null));
      var version = nonEmptyString(def(integration, 'version', null));
      tableCell(row, version === null ? dashSpan() : el('span', '', version));
      var capabilities = def(integration, 'capabilities', null);
      var capCell = el('td');
      if (Array.isArray(capabilities) && capabilities.length) {
        var list = el('div', 'cap-list');
        capabilities.forEach(function (capability) {
          var text = nonEmptyString(capability);
          if (text !== null) list.appendChild(makeChip(text, 'tone-info'));
        });
        capCell.appendChild(list);
      } else {
        capCell.appendChild(dashSpan());
      }
      row.appendChild(capCell);
      var error = nonEmptyString(def(integration, 'last_error', null));
      tableCell(row, error === null ? dashSpan() : el('span', 'error-text', error));
      table.tbody.appendChild(row);
    });
    var wrap = el('div', 'table-scroll');
    wrap.appendChild(table.table);
    host.appendChild(wrap);
    appendBoundedNote(host, Math.min(integrations.length, INTEGRATION_CAP), integrations.length, 'integrations');
  }

  /* ------------------------------------------------------------------ */

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
}());
