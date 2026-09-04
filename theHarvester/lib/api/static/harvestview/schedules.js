'use strict';

const state = {
  sources: [],
  runs: [],
  schedules: [],
  health: null,
  dispatchTable: null,
  editingSchedule: null,
  prerequisitesReady: false,
};

const elements = {};
const ACTIVE_FLAGS = ['dns_brute', 'dns_resolve', 'dns_lookup', 'routeviews', 'shodan', 'screenshot', 'takeover', 'api_scan'];
const AUTHORIZATION_FLAGS = new Set(['dns_brute', 'dns_resolve', 'dns_lookup', 'screenshot', 'takeover', 'api_scan']);

function byId(id) {
  return document.getElementById(id);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: 'same-origin',
    ...options,
    headers: {
      Accept: 'application/json',
      ...(options.body ? {'Content-Type': 'application/json'} : {}),
      ...(options.headers || {}),
    },
  });
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const payload = await response.json();
      if (typeof payload.detail === 'string') {
        detail = payload.detail;
      } else if (payload.detail) {
        detail = JSON.stringify(payload.detail);
      }
    } catch (_error) {
      // Keep the HTTP status when the body is not JSON.
    }
    throw new Error(detail);
  }
  if (response.status === 204) {
    return null;
  }
  return response.json();
}

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.hidden = false;
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => {
    elements.toast.hidden = true;
  }, 4500);
}

function showFormError(message) {
  elements.formError.textContent = message;
  elements.formError.hidden = !message;
}

function failureMessage(action, error, recovery) {
  const detail = error instanceof Error ? error.message : String(error);
  return `${action}: ${detail.endsWith('.') ? detail : `${detail}.`} ${recovery}`;
}

function normalizeTarget(value) {
  const target = value.trim().replace(/\.+$/, '');
  if (/^as\d+$/i.test(target)) {
    return `AS${Number(target.slice(2))}`;
  }
  const lowered = target.toLowerCase();
  try {
    const hostname = new URL(`http://${lowered.includes(':') ? `[${lowered}]` : lowered}`).hostname;
    return hostname.startsWith('[') ? hostname.slice(1, -1) : hostname;
  } catch {
    return lowered;
  }
}

function parseTargets() {
  const values = elements.targets.value
    .split(/[\n,]+/)
    .map(normalizeTarget)
    .filter(Boolean);
  return [...new Set(values)];
}

function updateTargetSummary() {
  const count = parseTargets().length;
  elements.targetSummary.textContent = `${count.toLocaleString()} unique target${count === 1 ? '' : 's'}`;
}

function localDateTimeValue(date) {
  const pad = (value) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function zonedDateTimeValue(value, timeZone) {
  const parts = zonedParts(new Date(value).valueOf(), timeZone);
  const pad = (part) => String(part).padStart(2, '0');
  return `${parts.year}-${pad(parts.month)}-${pad(parts.day)}T${pad(parts.hour)}:${pad(parts.minute)}`;
}

function zonedParts(epochMilliseconds, timeZone) {
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  });
  const parts = Object.fromEntries(formatter.formatToParts(new Date(epochMilliseconds)).map((part) => [part.type, part.value]));
  return {
    year: Number(parts.year),
    month: Number(parts.month),
    day: Number(parts.day),
    hour: Number(parts.hour),
    minute: Number(parts.minute),
    second: Number(parts.second),
  };
}

function zonedLocalToIso(localValue, timeZone) {
  if (!localValue) {
    throw new Error('Choose a start date and time.');
  }
  try {
    new Intl.DateTimeFormat('en-US', {timeZone}).format();
  } catch (_error) {
    throw new Error('Enter a valid IANA timezone, such as America/New_York.');
  }
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(localValue);
  if (!match) {
    throw new Error('Start time is invalid.');
  }
  const desired = {
    year: Number(match[1]),
    month: Number(match[2]),
    day: Number(match[3]),
    hour: Number(match[4]),
    minute: Number(match[5]),
    second: 0,
  };
  const desiredAsUtc = Date.UTC(desired.year, desired.month - 1, desired.day, desired.hour, desired.minute, 0);
  let guess = desiredAsUtc;
  for (let iteration = 0; iteration < 4; iteration += 1) {
    const actual = zonedParts(guess, timeZone);
    const actualAsUtc = Date.UTC(actual.year, actual.month - 1, actual.day, actual.hour, actual.minute, actual.second);
    const delta = desiredAsUtc - actualAsUtc;
    guess += delta;
    if (delta === 0) {
      return new Date(guess).toISOString();
    }
  }
  const actual = zonedParts(guess, timeZone);
  if (Object.keys(desired).some((key) => actual[key] !== desired[key])) {
    throw new Error('That local time does not exist in the selected timezone because of a daylight-saving transition.');
  }
  return new Date(guess).toISOString();
}

function formatDate(value) {
  if (!value) {
    return '—';
  }
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) {
    return value;
  }
  return new Intl.DateTimeFormat(undefined, {dateStyle: 'medium', timeStyle: 'short'}).format(date);
}

function formatScheduleDate(value, timeZone) {
  if (!value) {
    return '—';
  }
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) {
    return value;
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone,
  }).format(date);
}

function describeTiming(timing) {
  const interval = timing.interval === 1 ? '' : ` every ${timing.interval}`;
  if (timing.frequency === 'once') {
    return `Once at ${formatDate(timing.start_at)}`;
  }
  if (timing.frequency === 'weekly') {
    const labels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const days = timing.weekdays.map((day) => labels[day - 1]).join(', ');
    return `${interval ? `Every ${timing.interval} weeks` : 'Weekly'} on ${days} (${timing.timezone})`;
  }
  const units = {hourly: 'hours', daily: 'days', monthly: 'months'};
  return `${interval ? `Every ${timing.interval} ${units[timing.frequency]}` : timing.frequency[0].toUpperCase() + timing.frequency.slice(1)} (${timing.timezone})`;
}

function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem('runs-theme', theme);
  elements.themeButton.textContent = `Theme: ${theme}`;
}

function cycleTheme() {
  const current = document.documentElement.dataset.theme || 'system';
  const next = current === 'system' ? 'light' : current === 'light' ? 'dark' : 'system';
  setTheme(next);
}

function renderSources() {
  const passive = state.sources.filter((source) => source.activity === 'P0');
  elements.sourceGrid.replaceChildren();
  for (const source of passive) {
    const label = document.createElement('label');
    label.className = `source-option${source.ready ? '' : ' is-unready'}`;
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.value = source.name;
    checkbox.dataset.source = source.name;
    checkbox.disabled = !source.ready;
    const copy = document.createElement('span');
    const title = document.createElement('strong');
    title.textContent = source.name;
    const details = document.createElement('small');
    details.textContent = source.ready ? source.capabilities.join(' · ') : `Credentials required: ${source.credentials.join(', ')}`;
    copy.append(title, details);
    label.append(checkbox, copy);
    elements.sourceGrid.append(label);
  }
  const readyCount = passive.filter((source) => source.ready).length;
  elements.sourceReadiness.textContent = `${readyCount} of ${passive.length} passive sources are ready.`;
}

function renderRuns() {
  elements.templateRun.innerHTML = '<option value="">Choose a run</option>';
  for (const run of state.runs.filter((item) => item.origin === 'local')) {
    const option = document.createElement('option');
    option.value = run.run_id;
    option.textContent = `${run.target} · ${run.status} · ${formatDate(run.created_at)}`;
    elements.templateRun.append(option);
  }
}

function renderHealth() {
  const health = state.health;
  if (!health) {
    elements.runtimeHealth.textContent = 'Scheduler health unavailable';
  } else if (!health.scheduler_enabled && !health.worker_enabled) {
    elements.runtimeHealth.textContent = 'Preview mode · execution disabled';
  } else {
    const scheduler = health.scheduler_available ? 'Scheduler ready' : 'Scheduler unavailable';
    const worker = health.worker_available ? 'Worker ready' : 'Worker unavailable';
    elements.runtimeHealth.textContent = `${scheduler} · ${worker}`;
  }
}

function setScheduleAvailability(ready) {
  state.prerequisitesReady = ready;
  elements.createButton.disabled = !ready;
  elements.scheduleList.querySelectorAll('[data-action]').forEach((button) => {
    button.disabled = !ready;
  });
}

function scheduleMutationAvailable() {
  if (state.prerequisitesReady) {
    return true;
  }
  showToast('Schedule controls are unavailable. Refresh prerequisites before making changes.');
  return false;
}

function renderSchedules() {
  elements.scheduleLoading.hidden = true;
  elements.scheduleCount.textContent = state.schedules.length.toLocaleString();
  elements.scheduleEmpty.hidden = state.schedules.length !== 0;
  elements.scheduleList.replaceChildren();

  for (const schedule of state.schedules) {
    const card = document.createElement('article');
    card.className = `schedule-card${schedule.enabled ? '' : ' is-paused'}`;
    const preview = schedule.targets.slice(0, 3).join(', ') + (schedule.targets.length > 3 ? `, +${schedule.targets.length - 3} more` : '');
    const upcoming = schedule.upcoming_occurrences || [];
    const upcomingMarkup = schedule.enabled
      ? `<details class="upcoming-schedule">
          <summary>Upcoming occurrences</summary>
          ${upcoming.length > 0
            ? `<ol class="upcoming-occurrences">${upcoming.map((occurrence) => `<li>${escapeHtml(formatScheduleDate(occurrence, schedule.timing.timezone))}</li>`).join('')}</ol>`
            : '<p class="upcoming-empty">No future occurrences.</p>'}
        </details>`
      : '<p class="upcoming-empty">Paused — resume to calculate upcoming occurrences.</p>';
    card.innerHTML = `
      <div class="schedule-card-header">
        <div>
          <h3>${escapeHtml(schedule.name)}</h3>
          <p class="schedule-card-subtitle">${escapeHtml(describeTiming(schedule.timing))}</p>
        </div>
        <span class="schedule-status ${schedule.enabled ? 'enabled' : ''}">${schedule.enabled ? 'Enabled' : 'Paused'}</span>
      </div>
      <p class="schedule-target-preview">${escapeHtml(preview)}</p>
      <dl class="schedule-facts">
        <div><dt>Targets</dt><dd>${schedule.targets.length.toLocaleString()}</dd></div>
        <div><dt>Next run</dt><dd>${escapeHtml(formatScheduleDate(schedule.next_run_at, schedule.timing.timezone))}</dd></div>
        <div><dt>Last run</dt><dd>${escapeHtml(formatDate(schedule.last_run_at))}</dd></div>
      </dl>
      ${upcomingMarkup}
      ${schedule.last_error ? `<p class="schedule-error">${escapeHtml(schedule.last_error)}</p>` : ''}
      <div class="schedule-card-footer">
        <span class="schedule-card-subtitle">${escapeHtml(schedule.overlap_policy === 'skip' ? 'Skips overlapping batches' : 'Queues overlapping batches')}</span>
        <div class="compact-actions">
          <button type="button" class="button small" data-action="edit">Edit</button>
          <button type="button" class="button small" data-action="dispatches">History</button>
          <button type="button" class="button small" data-action="run-now">Run now</button>
          <button type="button" class="button small" data-action="toggle">${schedule.enabled ? 'Pause' : 'Resume'}</button>
          <button type="button" class="button small danger" data-action="delete">Delete</button>
        </div>
      </div>`;
    card.querySelector('[data-action="edit"]').addEventListener('click', () => editSchedule(schedule));
    card.querySelector('[data-action="dispatches"]').addEventListener('click', () => openDispatches(schedule));
    card.querySelector('[data-action="run-now"]').addEventListener('click', () => runNow(schedule));
    card.querySelector('[data-action="toggle"]').addEventListener('click', () => toggleSchedule(schedule));
    card.querySelector('[data-action="delete"]').addEventListener('click', () => deleteSchedule(schedule));
    elements.scheduleList.append(card);
  }
  setScheduleAvailability(state.prerequisitesReady);
}

function updateTemplatePanels() {
  const mode = document.querySelector('input[name="template-mode"]:checked').value;
  elements.cloneTemplatePanel.hidden = mode !== 'clone';
  elements.passiveTemplatePanel.hidden = mode !== 'passive';
  updateAuthorization();
}

function updateTimingFields() {
  const frequency = elements.frequency.value;
  elements.intervalLabel.hidden = frequency === 'once';
  elements.weekdayPanel.hidden = frequency !== 'weekly';
  elements.monthlyHelp.hidden = frequency !== 'monthly';
  const units = {hourly: 'hour(s)', daily: 'day(s)', weekly: 'week(s)', monthly: 'month(s)'};
  elements.intervalUnit.textContent = units[frequency] || '';
  if (frequency === 'once') {
    elements.interval.value = '1';
  }
  if (frequency === 'weekly' && !elements.weekdayPanel.querySelector('input:checked')) {
    const local = new Date(elements.start.value || Date.now());
    const isoDay = local.getDay() === 0 ? 7 : local.getDay();
    const checkbox = elements.weekdayPanel.querySelector(`input[value="${isoDay}"]`);
    if (checkbox) checkbox.checked = true;
  }
}

function selectedFlags() {
  return Object.fromEntries(ACTIVE_FLAGS.map((flag) => [flag, Boolean(document.querySelector(`[data-run-flag="${flag}"]`)?.checked)]));
}

function runNeedsAuthorization(run) {
  return [...AUTHORIZATION_FLAGS].some((flag) => Boolean(run[flag]))
    || Number(run.dns_recursive_depth || 0) > 0
    || Boolean(run.vhost || run.vhost_endpoint || run.vhost_candidates?.length);
}

function updateAuthorization() {
  const mode = document.querySelector('input[name="template-mode"]:checked').value;
  const selectedRun = state.runs.find((run) => run.run_id === elements.templateRun.value);
  const editedRun = {...(state.editingSchedule?.run || {}), ...selectedFlags()};
  const requiresAuthorization = mode === 'passive'
    ? runNeedsAuthorization(editedRun)
    : selectedRun?.activities?.some((activity) => activity === 'P1' || activity === 'P2') || false;
  elements.authorizationRow.hidden = !requiresAuthorization;
  if (!requiresAuthorization) {
    elements.authorizationConfirmation.checked = false;
  }
}

function buildTiming() {
  const frequency = elements.frequency.value;
  const weekdays = frequency === 'weekly'
    ? [...elements.weekdayPanel.querySelectorAll('input:checked')].map((input) => Number(input.value))
    : [];
  if (frequency === 'weekly' && weekdays.length === 0) {
    throw new Error('Select at least one weekday.');
  }
  return {
    frequency,
    start_at: zonedLocalToIso(elements.start.value, elements.timezone.value.trim()),
    timezone: elements.timezone.value.trim(),
    interval: frequency === 'once' ? 1 : Number(elements.interval.value),
    weekdays,
  };
}

async function buildRunTemplate(targets) {
  const mode = document.querySelector('input[name="template-mode"]:checked').value;
  if (mode === 'clone') {
    const runId = elements.templateRun.value;
    if (!runId) {
      throw new Error('Choose an existing run to clone.');
    }
    const detail = await api(`/api/v1/runs/${encodeURIComponent(runId)}`);
    if (!detail.request || !Array.isArray(detail.request.sources)) {
      throw new Error('The selected record is not a reusable local run.');
    }
    if (runNeedsAuthorization(detail.request) && !elements.authorizationConfirmation.checked) {
      throw new Error('Confirm authorization for the cloned DNS or direct-interaction activity.');
    }
    return {...detail.request, target: targets[0]};
  }

  const existingRun = state.editingSchedule?.run || {};
  const knownSources = new Set(state.sources.map((source) => source.name));
  const preservedSources = (existingRun.sources || []).filter((source) => !knownSources.has(source));
  const selectedSources = [...elements.sourceGrid.querySelectorAll('input:checked')].map((input) => input.value);
  const sources = [...preservedSources, ...selectedSources];
  const flags = selectedFlags();
  if (!state.editingSchedule && sources.length === 0 && !Object.values(flags).some(Boolean)) {
    throw new Error('Select at least one passive source or optional action.');
  }
  const deadline = elements.deadline.value.trim();
  const run = {
    ...existingRun,
    target: targets[0],
    sources,
    limit: Number(elements.limit.value),
    start: existingRun.start ?? 0,
    source_workers: Number(elements.sourceWorkers.value),
    deadline_seconds: deadline ? Number(deadline) : null,
    ...flags,
  };
  if (runNeedsAuthorization(run) && !elements.authorizationConfirmation.checked) {
    throw new Error('Confirm authorization for the selected DNS or direct-interaction activity.');
  }
  return run;
}

async function submitSchedule(event) {
  event.preventDefault();
  showFormError('');
  if (!scheduleMutationAvailable()) {
    return;
  }
  elements.createButton.disabled = true;
  try {
    const editing = state.editingSchedule;
    const targets = parseTargets();
    if (targets.length === 0) {
      throw new Error('Enter at least one authorized target.');
    }
    if (targets.length > 10000) {
      throw new Error('A single schedule supports up to 10,000 targets. Split larger inventories into multiple schedules.');
    }
    const enabled = editing
      ? (await api(`/api/v1/schedules/${encodeURIComponent(editing.schedule_id)}`)).enabled
      : true;
    const payload = {
      name: elements.name.value.trim(),
      targets,
      run: await buildRunTemplate(targets),
      timing: buildTiming(),
      enabled,
      overlap_policy: elements.overlapPolicy.value,
    };
    const path = editing ? `/api/v1/schedules/${encodeURIComponent(editing.schedule_id)}` : '/api/v1/schedules';
    await api(path, {method: editing ? 'PUT' : 'POST', body: JSON.stringify(payload)});
    showToast(editing
      ? `Saved changes to “${payload.name}”.`
      : `Created “${payload.name}” for ${targets.length.toLocaleString()} target${targets.length === 1 ? '' : 's'}.`);
    resetScheduleForm();
    await loadSchedules();
  } catch (error) {
    showFormError(failureMessage(
      state.editingSchedule ? 'Could not save schedule' : 'Could not create schedule',
      error,
      'Review the schedule values and try again.',
    ));
  } finally {
    elements.createButton.disabled = !state.prerequisitesReady;
  }
}

function resetScheduleForm() {
  state.editingSchedule = null;
  elements.form.reset();
  elements.builderTitle.textContent = 'Create a schedule';
  elements.createButton.textContent = 'Create schedule';
  elements.cancelEditButton.hidden = true;
  elements.timezone.value = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  elements.start.value = localDateTimeValue(new Date(Date.now() + 5 * 60 * 1000));
  showFormError('');
  updateTimingFields();
  updateTargetSummary();
  updateTemplatePanels();
}

function cancelScheduleEdit() {
  resetScheduleForm();
  elements.name.focus();
}

function editSchedule(schedule) {
  if (!scheduleMutationAvailable()) {
    return;
  }
  resetScheduleForm();
  state.editingSchedule = schedule;
  elements.builderTitle.textContent = 'Edit schedule';
  elements.createButton.textContent = 'Save changes';
  elements.cancelEditButton.hidden = false;
  elements.name.value = schedule.name;
  elements.targets.value = schedule.targets.join('\n');
  elements.frequency.value = schedule.timing.frequency;
  elements.start.value = zonedDateTimeValue(schedule.timing.start_at, schedule.timing.timezone);
  elements.timezone.value = schedule.timing.timezone;
  elements.interval.value = String(schedule.timing.interval);
  elements.overlapPolicy.value = schedule.overlap_policy;
  const weekdays = new Set(schedule.timing.weekdays);
  elements.weekdayPanel.querySelectorAll('input').forEach((input) => { input.checked = weekdays.has(Number(input.value)); });
  const sources = new Set(schedule.run.sources);
  elements.sourceGrid.querySelectorAll('input').forEach((input) => { input.checked = sources.has(input.value); });
  document.querySelectorAll('[data-run-flag]').forEach((input) => { input.checked = Boolean(schedule.run[input.dataset.runFlag]); });
  elements.limit.value = String(schedule.run.limit);
  elements.sourceWorkers.value = String(schedule.run.source_workers);
  elements.deadline.value = schedule.run.deadline_seconds == null ? '' : String(schedule.run.deadline_seconds);
  updateTimingFields();
  updateTargetSummary();
  updateTemplatePanels();
  const behavior = window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth';
  elements.form.scrollIntoView({behavior, block: 'start'});
  elements.name.focus();
}

async function toggleSchedule(schedule) {
  if (!scheduleMutationAvailable()) {
    return;
  }
  try {
    const action = schedule.enabled ? 'pause' : 'resume';
    await api(`/api/v1/schedules/${encodeURIComponent(schedule.schedule_id)}/${action}`, {method: 'POST'});
    showToast(`${schedule.enabled ? 'Paused' : 'Resumed'} “${schedule.name}”.`);
    await loadSchedules();
  } catch (error) {
    showToast(failureMessage(`Could not ${schedule.enabled ? 'pause' : 'resume'} “${schedule.name}”`, error, 'Refresh and try again.'));
  }
}

async function runNow(schedule) {
  if (!scheduleMutationAvailable()) {
    return;
  }
  if (!window.confirm(`Queue ${schedule.targets.length.toLocaleString()} run(s) for “${schedule.name}” now?`)) {
    return;
  }
  try {
    const result = await api(`/api/v1/schedules/${encodeURIComponent(schedule.schedule_id)}/run-now`, {method: 'POST'});
    showToast(`Queued ${result.run_ids.length.toLocaleString()} run(s); skipped ${result.skipped_targets.length.toLocaleString()}.`);
    await loadSchedules();
  } catch (error) {
    showToast(failureMessage(`Could not queue “${schedule.name}”`, error, 'Check worker availability and try again.'));
  }
}

async function deleteSchedule(schedule) {
  if (!scheduleMutationAvailable()) {
    return;
  }
  if (!window.confirm(`Delete “${schedule.name}”? Existing run evidence will not be deleted.`)) {
    return;
  }
  try {
    await api(`/api/v1/schedules/${encodeURIComponent(schedule.schedule_id)}`, {method: 'DELETE'});
    showToast(`Deleted “${schedule.name}”.`);
    await loadSchedules();
  } catch (error) {
    showToast(failureMessage(`Could not delete “${schedule.name}”`, error, 'Refresh and try again.'));
  }
}

function showDispatchMessage(message) {
  elements.dispatchMessage.textContent = message;
  elements.dispatchMessage.hidden = !message;
  elements.dispatchGrid.hidden = Boolean(message);
}

function renderDispatches(dispatches) {
  state.dispatchTable?.destroy();
  state.dispatchTable = null;
  if (dispatches.length === 0) {
    showDispatchMessage('No scheduled runs have been queued yet.');
    return;
  }
  showDispatchMessage('');
  state.dispatchTable = new Tabulator(elements.dispatchGrid, {
    data: dispatches,
    layout: 'fitColumns',
    responsiveLayout: 'collapse',
    pagination: true,
    paginationSize: 25,
    paginationSizeSelector: [25, 50, 100],
    initialSort: [{column: 'scheduled_for', dir: 'desc'}],
    columns: [
      {title: 'Scheduled for', field: 'scheduled_for', minWidth: 190, headerFilter: 'input', formatter: (cell) => formatDate(cell.getValue())},
      {title: 'Target', field: 'target', minWidth: 180, headerFilter: 'input', tooltip: true},
      {title: 'State', field: 'state', width: 130, headerFilter: 'input'},
      {
        title: 'Run',
        field: 'run_id',
        width: 105,
        formatter: (cell) => {
          const runId = cell.getValue();
          const link = document.createElement('a');
          link.href = '/';
          link.title = `Run ${runId} · Open HarvestView and search for this run ID`;
          link.textContent = runId.slice(0, 8);
          return link;
        },
      },
      {title: 'Error', field: 'error', minWidth: 220, headerFilter: 'input', tooltip: true, formatter: (cell) => cell.getValue() || '—'},
    ],
  });
}

async function openDispatches(schedule) {
  elements.dispatchTitle.textContent = `Scheduled runs: ${schedule.name}`;
  elements.dispatchSubtitle.textContent = `${schedule.targets.length.toLocaleString()} target${schedule.targets.length === 1 ? '' : 's'}`;
  state.dispatchTable?.destroy();
  state.dispatchTable = null;
  showDispatchMessage('Loading…');
  elements.dispatchDialog.showModal();
  try {
    const dispatches = await api(`/api/v1/schedules/${encodeURIComponent(schedule.schedule_id)}/dispatches?limit=1000`);
    renderDispatches(dispatches);
  } catch (error) {
    showDispatchMessage(failureMessage('Could not load dispatch history', error, 'Close this dialog, refresh, and try again.'));
  }
}

async function loadSchedules() {
  state.schedules = await api('/api/v1/schedules?limit=500');
  renderSchedules();
}

async function loadInitialData() {
  const selectedSources = new Set([...elements.sourceGrid.querySelectorAll('input:checked')].map((input) => input.value));
  const selectedTemplateRun = elements.templateRun.value;
  setScheduleAvailability(false);
  elements.runtimeHealth.textContent = 'Checking scheduler…';
  elements.sourceReadiness.textContent = 'Loading source catalog…';
  elements.scheduleLoading.textContent = 'Loading schedules…';
  elements.scheduleLoading.hidden = false;
  try {
    const [catalog, runs, schedules, health] = await Promise.all([
      api('/api/v1/sources'),
      api('/api/v1/runs?limit=500'),
      api('/api/v1/schedules?limit=500'),
      api('/api/v1/schedules/health'),
    ]);
    state.sources = catalog.sources || [];
    state.runs = runs;
    state.schedules = schedules;
    state.health = health;
    renderSources();
    elements.sourceGrid.querySelectorAll('input').forEach((input) => {
      input.checked = !input.disabled && selectedSources.has(input.value);
    });
    renderRuns();
    if (selectedTemplateRun && elements.templateRun.querySelector(`option[value="${CSS.escape(selectedTemplateRun)}"]`)) {
      elements.templateRun.value = selectedTemplateRun;
    }
    renderSchedules();
    renderHealth();
    setScheduleAvailability(true);
  } catch (_error) {
    elements.runtimeHealth.textContent = 'Schedules unavailable';
    elements.sourceReadiness.textContent = 'Schedule prerequisites unavailable.';
    elements.scheduleLoading.textContent = 'Schedule prerequisites are unavailable. Configure local access and confirm scheduler availability, then Refresh.';
    elements.scheduleLoading.hidden = false;
    setScheduleAvailability(false);
  }
}

function initializeElements() {
  Object.assign(elements, {
    themeButton: byId('theme-button'),
    runtimeHealth: byId('runtime-health'),
    refreshButton: byId('refresh-button'),
    toast: byId('toast'),
    form: byId('schedule-form'),
    name: byId('schedule-name'),
    targets: byId('schedule-targets'),
    targetSummary: byId('target-summary'),
    cloneTemplatePanel: byId('clone-template-panel'),
    passiveTemplatePanel: byId('passive-template-panel'),
    templateRun: byId('template-run'),
    sourceGrid: byId('source-grid'),
    sourceReadiness: byId('source-readiness'),
    frequency: byId('schedule-frequency'),
    start: byId('schedule-start'),
    timezone: byId('schedule-timezone'),
    interval: byId('schedule-interval'),
    intervalLabel: byId('interval-label'),
    intervalUnit: byId('interval-unit'),
    monthlyHelp: byId('monthly-help'),
    overlapPolicy: byId('overlap-policy'),
    weekdayPanel: byId('weekday-panel'),
    limit: byId('run-limit'),
    sourceWorkers: byId('source-workers'),
    deadline: byId('run-deadline'),
    authorizationRow: byId('authorization-row'),
    authorizationConfirmation: byId('authorization-confirmation'),
    formError: byId('form-error'),
    createButton: byId('create-schedule-button'),
    cancelEditButton: byId('cancel-edit-button'),
    builderTitle: byId('builder-title'),
    scheduleLoading: byId('schedule-loading'),
    scheduleEmpty: byId('schedule-empty'),
    scheduleList: byId('schedule-list'),
    scheduleCount: byId('schedule-count'),
    dispatchDialog: byId('dispatch-dialog'),
    dispatchTitle: byId('dispatch-title'),
    dispatchSubtitle: byId('dispatch-subtitle'),
    dispatchGrid: byId('dispatch-grid'),
    dispatchMessage: byId('dispatch-message'),
  });
}

function bindEvents() {
  elements.themeButton.addEventListener('click', cycleTheme);
  elements.refreshButton.addEventListener('click', loadInitialData);
  elements.form.addEventListener('submit', submitSchedule);
  elements.cancelEditButton.addEventListener('click', cancelScheduleEdit);
  elements.targets.addEventListener('input', updateTargetSummary);
  elements.frequency.addEventListener('change', updateTimingFields);
  elements.templateRun.addEventListener('change', updateAuthorization);
  document.querySelectorAll('input[name="template-mode"]').forEach((input) => input.addEventListener('change', updateTemplatePanels));
  document.querySelectorAll('[data-run-flag]').forEach((input) => input.addEventListener('change', updateAuthorization));
  byId('select-ready-passive').addEventListener('click', () => {
    elements.sourceGrid.querySelectorAll('input:not(:disabled)').forEach((input) => { input.checked = true; });
  });
  byId('clear-sources').addEventListener('click', () => {
    elements.sourceGrid.querySelectorAll('input').forEach((input) => { input.checked = false; });
  });
  byId('close-dispatch-dialog').addEventListener('click', () => elements.dispatchDialog.close());
}

function initializeDefaults() {
  setTheme(localStorage.getItem('runs-theme') || 'system');
  resetScheduleForm();
  setScheduleAvailability(false);
}

document.addEventListener('DOMContentLoaded', () => {
  initializeElements();
  bindEvents();
  initializeDefaults();
  loadInitialData();
});
