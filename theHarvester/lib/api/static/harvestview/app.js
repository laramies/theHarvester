(() => {
  'use strict';

  const $ = selector => document.querySelector(selector);
  const $$ = selector => [...document.querySelectorAll(selector)];
  const ROUTE_ORDER = [
    'hostname', 'ip', 'prefix', 'asn', 'email', 'url', 'person', 'person-link', 'takeover', 'shodan',
    'scope-extension', 'external-relationship', 'other'
  ];
  const ROUTE_LABELS = {
    hostname: 'Hostnames', ip: 'IP addresses', prefix: 'Network prefixes', asn: 'ASNs', email: 'Emails', url: 'URLs',
    person: 'People', 'person-link': 'People links', takeover: 'Takeover evidence', shodan: 'Shodan evidence',
    'scope-extension': 'Scope extensions', 'external-relationship': 'External relationships', other: 'Other'
  };
  const ACTION_FIELDS = {'dns-recursive': 'dns_recursive_depth'};
  const SQLITE_SUFFIXES = ['.sqlite', '.sqlite3', '.db'];
  const state = {
    runs: [],
    selectedId: null,
    detail: null,
    sources: [],
    actions: [],
    selectedSources: new Set(['crtsh']),
    route: null,
    theme: localStorage.getItem('runs-theme') || 'system',
    pollTimer: null,
    pollErrorShown: false,
    resultTable: null,
    screenshotUrls: new Map(),
  };

  const nodes = {
    themeButton: $('#theme-button'), importButton: $('#import-button'), newRunButton: $('#new-run-button'),
    loading: $('#loading-state'), empty: $('#empty-state'), detail: $('#run-detail'),
    workspaceError: $('#workspace-error'), workspaceErrorMessage: $('#workspace-error-message'),
    retryWorkspace: $('#retry-workspace-button'),
    runCount: $('#run-count'), historySearch: $('#history-search'), runList: $('#run-list'), historyEmpty: $('#history-empty'),
    detailTarget: $('#detail-target'), detailRunId: $('#detail-run-id'), statusChips: $('#status-chips'), cancel: $('#cancel-run-button'),
    runFacts: $('#run-facts'), lifecycleTrack: $('#lifecycle-track'), lifecycleNote: $('#lifecycle-note'),
    resultsSection: $('#results-section'),
    activityBands: $('#activity-bands'), requestOptions: $('#request-options'), providerBody: $('#provider-body'),
    providerSummary: $('#provider-summary'), providerOutcomeSummary: $('#provider-outcome-summary'), providerEmpty: $('#provider-empty'),
    providerDetails: $('#provider-details'), resultsSummary: $('#results-summary'),
    routeTabs: $('#route-tabs'), resultsEmpty: $('#results-empty'), resultsEmptyTitle: $('#results-empty-title'),
    resultsEmptyCopy: $('#results-empty-copy'), resultWorkbench: $('#result-workbench'),
    routeOverflowCue: $('#route-overflow-cue'),
    resultSearch: $('#result-search'), routeCount: $('#route-count'), copySelected: $('#copy-route-button'),
    exportJsonl: $('#export-jsonl-button'), screenshotSection: $('#screenshot-section'),
    screenshotGallery: $('#screenshot-gallery'), logSection: $('#log-section'), logOutput: $('#run-log-output'),
    newRunDialog: $('#new-run-dialog'), newRunForm: $('#new-run-form'), sourceSearch: $('#source-search'), sourceGroups: $('#source-groups'),
    sourceCapability: $('#source-capability'), selectCapability: $('#select-capability-button'),
    selectP0: $('#select-p0-button'), clearP0: $('#clear-p0-button'),
    dnsResolvers: $('#dns-resolvers'), dnsResolverFile: $('#dns-resolver-file'),
    activitySummary: $('#activity-summary'), newRunError: $('#new-run-error'), submitRun: $('#submit-run-button'),
    importDialog: $('#import-dialog'), importForm: $('#import-form'), resultFile: $('#result-file'), fileLabel: $('#file-label'),
    importError: $('#import-error'), submitImport: $('#submit-import-button'), screenshotDialog: $('#screenshot-dialog'),
    screenshotDialogTitle: $('#screenshot-dialog-title'), screenshotDialogImage: $('#screenshot-dialog-image'),
    toast: $('#toast'), announcer: $('#announcer'),
  };

  for (const tip of $$('.help-tip')) tip.setAttribute('aria-description', tip.dataset.tooltip);

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>'"]/g, character => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
    })[character]);
  }

  function safeClass(value) {
    return String(value ?? '').toLowerCase().replace(/[^a-z0-9-]/g, '-');
  }

  function errorMessage(payload, fallback) {
    const detail = payload?.detail;
    if (typeof detail === 'string') return detail;
    if (Array.isArray(detail)) return detail.map(item => item.msg || 'Invalid value').join('. ');
    return fallback;
  }

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    const response = await fetch(path, {...options, headers});
    if (!response.ok) {
      let payload = null;
      try { payload = await response.json(); } catch { /* response has no JSON body */ }
      const error = new Error(errorMessage(payload, `${response.status} ${response.statusText}`));
      error.status = response.status;
      throw error;
    }
    return response;
  }

  function announce(message) {
    nodes.announcer.textContent = '';
    requestAnimationFrame(() => { nodes.announcer.textContent = message; });
  }

  let toastTimer = null;
  function toast(message, isError = false) {
    clearTimeout(toastTimer);
    nodes.toast.textContent = message;
    nodes.toast.classList.toggle('error', isError);
    nodes.toast.hidden = false;
    toastTimer = setTimeout(() => { nodes.toast.hidden = true; }, 4200);
  }

  function dismissToast() {
    clearTimeout(toastTimer);
    nodes.toast.hidden = true;
  }

  function setBusy(button, busy, label) {
    if (!button.dataset.idleLabel) button.dataset.idleLabel = button.textContent;
    button.disabled = busy;
    button.textContent = busy ? label : button.dataset.idleLabel;
  }

  function showFormError(node, message) {
    node.textContent = message;
    node.hidden = !message;
  }

  function formatDate(value) {
    if (!value) return 'Not yet';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return new Intl.DateTimeFormat(undefined, {
      month: 'short', day: 'numeric', year: date.getFullYear() !== new Date().getFullYear() ? 'numeric' : undefined,
      hour: 'numeric', minute: '2-digit', second: '2-digit'
    }).format(date);
  }

  function formatDuration(started, completed) {
    if (!started) return 'Not started';
    if (!completed) return 'In progress';
    const seconds = Math.max(0, Math.round((new Date(completed) - new Date(started)) / 1000));
    if (!Number.isFinite(seconds)) return 'Unknown';
    if (seconds < 60) return `${seconds} sec`;
    const minutes = Math.floor(seconds / 60);
    return `${minutes} min ${seconds % 60} sec`;
  }

  function statusChip(status, prefix = '') {
    if (!status) return '';
    const label = prefix ? `${prefix}: ${status}` : status;
    return `<span class="status-chip ${safeClass(status)}">${escapeHtml(label)}</span>`;
  }

  function applyTheme() {
    if (!['system', 'light', 'dark'].includes(state.theme)) state.theme = 'system';
    document.documentElement.dataset.theme = state.theme;
    nodes.themeButton.textContent = `Theme: ${state.theme}`;
    nodes.themeButton.setAttribute('aria-label', `Color theme is ${state.theme}. Change color theme`);
    localStorage.setItem('runs-theme', state.theme);
  }

  function cycleTheme() {
    const themes = ['system', 'light', 'dark'];
    state.theme = themes[(themes.indexOf(state.theme) + 1) % themes.length];
    applyTheme();
    toast(`${state.theme[0].toUpperCase()}${state.theme.slice(1)} theme selected.`);
  }

  function openDialog(dialog, focusSelector) {
    const formError = dialog.querySelector('.form-error');
    if (formError) showFormError(formError, '');
    if (!dialog.open) dialog.showModal();
    const focusTarget = focusSelector ? dialog.querySelector(focusSelector) : dialog.querySelector('input, button');
    requestAnimationFrame(() => focusTarget?.focus());
  }

  function closeDialog(dialog) {
    if (dialog?.open) dialog.close();
  }

  async function loadWorkspace() {
    nodes.newRunButton.disabled = true;
    nodes.loading.hidden = false;
    nodes.empty.hidden = true;
    nodes.detail.hidden = true;
    nodes.workspaceError.hidden = true;
    const [catalogResponse, runsResponse] = await Promise.all([
      api('/api/v1/sources'), api('/api/v1/runs')
    ]);
    const catalog = await catalogResponse.json();
    state.sources = catalog.sources;
    state.actions = catalog.actions;
    nodes.newRunButton.disabled = false;
    const capabilities = [...new Set(state.sources.flatMap(source => source.capabilities || []))].sort();
    nodes.sourceCapability.innerHTML = '<option value="">Choose result type</option>' + capabilities.map(capability => `<option value="${escapeHtml(capability)}">${escapeHtml(capability)}</option>`).join('');
    state.runs = await runsResponse.json();
    nodes.loading.hidden = true;
    renderHistory();
    if (!state.runs.length) {
      state.selectedId = null;
      nodes.empty.hidden = false;
      return;
    }
    const preferred = state.runs.some(run => run.run_id === state.selectedId) ? state.selectedId : state.runs[0].run_id;
    await selectRun(preferred);
  }

  function filteredRuns() {
    const query = nodes.historySearch.value.trim().toLowerCase();
    if (!query) return state.runs;
    return state.runs.filter(run => [run.target, run.run_id, run.status, run.origin, ...(run.activities || [])].some(value => String(value).toLowerCase().includes(query)));
  }

  function renderHistory() {
    const focusedRunId = document.activeElement?.dataset.runId;
    nodes.runCount.textContent = state.runs.length;
    const runs = filteredRuns();
    nodes.historyEmpty.hidden = runs.length > 0;
    nodes.historyEmpty.querySelector('p').textContent = state.runs.length ? 'No runs match this search.' : 'No saved runs yet.';
    nodes.runList.innerHTML = runs.map(run => `
      <button class="run-item ${run.run_id === state.selectedId ? 'selected' : ''}" type="button"
        data-run-id="${escapeHtml(run.run_id)}" aria-pressed="${run.run_id === state.selectedId}">
        <span class="run-target" title="${escapeHtml(run.target)}">${escapeHtml(run.target)}</span>
        ${statusChip(run.status)}
        <span class="run-meta">${escapeHtml(formatDate(run.created_at))} · ${escapeHtml(run.origin)} · ${escapeHtml((run.activities || []).join('/'))}</span>
        <span class="run-results">${formatCount(run.result_count, 'result')}</span>
      </button>`).join('');
    if (focusedRunId) [...nodes.runList.children].find(button => button.dataset.runId === focusedRunId)?.focus({preventScroll: true});
  }

  function formatCount(value, singular, plural = `${singular}s`) {
    const count = Number(value || 0);
    return `${count.toLocaleString()} ${count === 1 ? singular : plural}`;
  }

  function isTerminalStatus(status) {
    return ['completed', 'failed', 'cancelled'].includes(status);
  }

  async function selectRun(runId) {
    stopPolling();
    state.selectedId = runId;
    state.detail = null;
    nodes.loading.hidden = false;
    nodes.detail.hidden = true;
    nodes.cancel.hidden = true;
    renderHistory();
    try {
      const response = await api(`/api/v1/runs/${encodeURIComponent(runId)}`);
      const detail = await response.json();
      if (state.selectedId !== runId) return null;
      state.detail = detail;
      renderDetail();
      if (!isTerminalStatus(state.detail.status)) startPolling();
      return null;
    } catch (error) {
      if (state.selectedId !== runId) return null;
      nodes.loading.hidden = true;
      toast(`Could not load the run: ${error.message}. Select it again to retry.`, true);
      return error;
    }
  }

  function renderFacts(run) {
    const facts = [
      ['Origin', run.origin], ['Submitted', formatDate(run.created_at)], ['Started', formatDate(run.started_at)],
      ['Duration', formatDuration(run.started_at, run.completed_at)], ['Results', Number(run.result_count || 0).toLocaleString()]
    ];
    nodes.runFacts.innerHTML = facts.map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`).join('');
  }

  function renderLifecycle(run) {
    const terminalLabel = run.status === 'completed' ? 'Completed' : run.status === 'failed' ? 'Failed' : run.status === 'cancelled' ? 'Cancelled' : 'Terminal';
    const steps = [['Submitted', run.created_at], ['Started', run.started_at]];
    if (run.cancellation_requested_at) steps.push(['Cancellation requested', run.cancellation_requested_at]);
    steps.push([terminalLabel, run.completed_at]);
    nodes.lifecycleTrack.innerHTML = steps.map(([label, time]) => `
      <li class="lifecycle-step ${time ? 'reached' : ''}"><strong>${escapeHtml(label)}</strong><span>${escapeHtml(formatDate(time))}</span></li>`).join('');
    const notes = {
      queued: 'Waiting for the single local worker.', running: 'The isolated child process owns the finite execution.',
      cancelling: 'Termination requested; forced termination follows after the grace period.', cancelled: 'The child can no longer produce work.',
      completed: 'Lifecycle is terminal. Evidence completeness is reported separately.', failed: run.error || 'The run ended without a successful lifecycle completion.'
    };
    nodes.lifecycleNote.textContent = notes[run.status] || '';
  }

  function renderAuthorization(run) {
    const active = new Set(run.activities || []);
    nodes.activityBands.innerHTML = ['P0', 'P1', 'P2'].map(activity => `
      <div class="activity-band ${active.has(activity) ? `active ${activity.toLowerCase()}` : ''}">
        <strong>${activity}</strong><span>${active.has(activity) ? 'Selected' : 'Off'}</span>
      </div>`).join('');
    const request = run.request || {};
    const sources = request.sources?.join(', ') || 'Not recorded';
    const options = [
      ['Sources', sources], ['Result limit', request.limit ?? 'Imported evidence'],
      ['Result start offset', request.start ?? 'Not recorded'],
      ['Whole-run deadline', request.deadline_seconds ? `${request.deadline_seconds} seconds` : 'Not applicable'],
      ['Proxy transport', request.proxies ? 'Selected' : 'Off'],
      ['DNS lookup (/24 reverse expansion)', request.dns_lookup ? 'Selected' : 'Off'],
      ['DNS resolution', request.dns_resolve ? 'Selected' : 'Off'], ['DNS brute force', request.dns_brute ? 'Selected' : 'Off'],
      ['DNS resolver vantages', request.dns_resolvers?.join(', ') || 'Not recorded'],
      ['Recursive DNS depth', request.dns_recursive_depth ?? 'Not recorded'],
      ['Recursive DNS query budget', request.dns_recursive_query_limit ?? 'Not recorded'],
      ['Recursive DNS runtime', request.dns_recursive_runtime_seconds ? `${request.dns_recursive_runtime_seconds} seconds` : 'Not recorded'],
      ['RouteViews enrichment', request.routeviews ? 'Selected' : 'Off'],
      ['Screenshots', request.screenshot ? 'Selected' : 'Off'],
      ['Takeover transport', request.takeover ? (request.proxies ? 'Configured proxy' : 'Direct') : 'Off'],
      ['API endpoint interaction', request.api_scan ? 'Selected' : 'Off'],
      ['Virtual-host discovery', request.vhost ? 'Selected' : 'Off'],
      ['Virtual-host endpoint override', request.vhost ? request.vhost_endpoint || 'Harvested IPs' : 'Not applicable'],
      ['Virtual-host candidates', request.vhost ? request.vhost_candidates?.join(', ') || 'Harvested hostnames' : 'Not applicable'],
      ['Virtual-host request budget', request.vhost ? request.vhost_request_limit : 'Not applicable'],
      ['Virtual-host runtime', request.vhost ? `${request.vhost_runtime_seconds} seconds` : 'Not applicable'],
      ['Virtual-host timeout', request.vhost ? `${request.vhost_timeout_seconds} seconds` : 'Not applicable'],
      ['Virtual-host concurrency', request.vhost ? request.vhost_concurrency : 'Not applicable'],
      ['Virtual-host TLS verification', request.vhost ? (request.vhost_insecure ? 'Disabled' : 'Enabled') : 'Not applicable']
    ];
    if (request.filename) options.unshift(['Imported file', request.filename]);
    nodes.requestOptions.innerHTML = options.map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`).join('');
  }

  function sourceName(execution) { return execution.source || 'Unknown source'; }
  function executionName(execution) { return execution.source || execution.action || 'Unknown producer'; }
  function executionKind(execution) { return execution.source ? 'Source' : execution.action ? 'Action' : 'Unknown'; }
  function credentialRequirement(source) {
    const credentials = source?.credentials || [];
    if (!credentials.length) return '';
    const labels = credentials.map(value => value.replaceAll('-', ' ').replace(/^api /, 'API '));
    return `Credentials required: ${labels.join(', ')}`;
  }

  function executionReason(execution) {
    const errorType = execution.error_type;
    if (execution.stop_reason === 'missing-credentials') {
      return 'Required credentials were not configured; add them, then retry.';
    }
    if (execution.source && execution.status === 'skipped' && errorType === 'SourceDidNotStart') {
      const requirement = credentialRequirement(state.sources.find(source => source.name === sourceName(execution)));
      return requirement
        ? `${requirement}. Source did not start; verify configuration or inspect the child log, then retry.`
        : 'Source did not start; inspect the child log, then retry.';
    }
    return errorType || execution.stop_reason?.replaceAll('-', ' ') || '-';
  }

  function renderExecutions(run) {
    const executions = [...(run.source_executions || []), ...(run.action_executions || [])];
    const counts = {completed: 0, partial: 0, skipped: 0, failed: 0, 'rate-limited': 0};
    let zeroResultCount = 0;
    for (const execution of executions) {
      if (Object.hasOwn(counts, execution.status)) counts[execution.status] += 1;
      if (execution.status === 'completed' && Number(execution.result_count || 0) === 0) zeroResultCount += 1;
    }
    nodes.providerSummary.textContent = executions.length;
    nodes.providerOutcomeSummary.hidden = executions.length === 0;
    nodes.providerOutcomeSummary.textContent = `${counts.completed} completed (${zeroResultCount} zero-result) / ${counts.partial} partial / ${counts.skipped} skipped / ${counts.failed} failed${counts['rate-limited'] ? ` / ${counts['rate-limited']} rate-limited` : ''}`;
    nodes.providerEmpty.hidden = executions.length > 0;
    nodes.providerBody.innerHTML = executions.map(execution => `
      <tr><td>${escapeHtml(executionName(execution))}</td><td>${executionKind(execution)}</td><td>${statusChip(execution.status || 'unknown')}</td>
      <td>${Number(execution.result_count || 0).toLocaleString()}</td><td>${execution.duration_ms == null ? '-' : `${Math.round(execution.duration_ms).toLocaleString()} ms`}</td>
      <td>${escapeHtml(executionReason(execution))}</td></tr>`).join('');
  }

  function groupedResults() {
    const groups = new Map();
    for (const result of state.detail?.results || []) {
      const type = result.type || 'other';
      if (!groups.has(type)) groups.set(type, []);
      groups.get(type).push(result);
    }
    return [...groups.entries()].sort(([left], [right]) => {
      const leftIndex = ROUTE_ORDER.indexOf(left);
      const rightIndex = ROUTE_ORDER.indexOf(right);
      return (leftIndex < 0 ? 999 : leftIndex) - (rightIndex < 0 ? 999 : rightIndex) || left.localeCompare(right);
    });
  }

  function dnsFormatter(cell) {
    const value = cell.getValue() || 'not-captured';
    return `<span class="dns-label ${safeClass(value)}">${escapeHtml(value.replaceAll('-', ' '))}</span>`;
  }

  function columnTextFilter(headerValue, rowValue) {
    const query = String(headerValue || '').trim().toLowerCase().replaceAll('-', ' ');
    const value = Array.isArray(rowValue) ? rowValue.join(' ') : rowValue || 'not-captured';
    return String(value).toLowerCase().replaceAll('-', ' ').includes(query);
  }

  function resultActionFormatter(cell) {
    const target = escapeHtml(cell.getRow().getData().value);
    return `<div class="result-actions">
      <button class="button small" type="button" data-run-action="screenshot" aria-label="Take screenshot of ${target} (P2)">Screenshot (P2)</button>
      <button class="button small" type="button" data-run-action="dns_brute" aria-label="DNS brute force ${target} (P1)">DNS brute (P1)</button>
    </div>`;
  }

  function vhostObservationsFormatter(cell) {
    const observations = Array.isArray(cell.getValue()) ? cell.getValue() : [];
    if (!observations.length) return 'No endpoint evidence';
    return `<div class="vhost-observations">${observations.map(observation => {
      const status = observation.status == null ? observation.phase || 'No response' : `HTTP ${observation.status}`;
      const location = observation.location ? ` → ${observation.location}` : '';
      const signals = Array.isArray(observation.distinct_signals) && observation.distinct_signals.length
        ? ` · ${observation.distinct_signals.join(', ')}`
        : '';
      const baselines = observation.context_status == null || observation.control_status == null
        ? ''
        : ` · IP HTTP ${observation.context_status} · unknown HTTP ${observation.control_status}`;
      const confirmation = observation.confirmation_body_sha256 ? ' · body confirmed' : '';
      const tls = observation.tls_verified == null ? '' : observation.tls_verified ? ' · TLS verified' : ' · TLS unverified';
      const text = `${observation.endpoint || 'Unknown endpoint'} · ${status}${location}${signals}${baselines}${confirmation}${tls}`;
      return `<span title="${escapeHtml(text)}">${escapeHtml(text)}</span>`;
    }).join('')}</div>`;
  }

  function vhostObservationsFilter(headerValue, rowValue) {
    const query = String(headerValue || '').trim().toLowerCase().replaceAll('-', ' ');
    const text = (Array.isArray(rowValue) ? rowValue : []).flatMap(observation => [
      observation.endpoint, observation.status, observation.phase, observation.location,
      observation.context_status, observation.control_status, observation.confirmation_body_sha256,
      observation.tls_verified, ...(observation.distinct_signals || [])
    ]).join(' ').toLowerCase().replaceAll('-', ' ');
    return text.includes(query);
  }

  function asnAttributionsFormatter(cell) {
    const observations = Array.isArray(cell.getValue()) ? cell.getValue() : [];
    if (!observations.length) return 'No organization attribution';
    return `<div class="vhost-observations">${observations.map(observation => {
      const subject = observation.subject || {};
      const producer = `${observation.producer_kind || 'producer'}:${observation.producer || 'unknown'}`;
      const text = `${observation.organization_label || 'Unknown organization'} · ${producer} · ${subject.type || 'subject'}:${subject.value || 'unknown'}`;
      return `<span title="${escapeHtml(text)}">${escapeHtml(text)}</span>`;
    }).join('')}</div>`;
  }

  function asnAttributionsFilter(headerValue, rowValue) {
    const query = String(headerValue || '').trim().toLowerCase().replaceAll('-', ' ');
    const text = (Array.isArray(rowValue) ? rowValue : []).flatMap(observation => [
      observation.organization_label, observation.producer_kind, observation.producer,
      observation.subject?.type, observation.subject?.value
    ]).join(' ').toLowerCase().replaceAll('-', ' ');
    return text.includes(query);
  }

  function networkObservationsFormatter(cell) {
    const observations = Array.isArray(cell.getValue()) ? cell.getValue() : [];
    if (!observations.length) return 'No routing evidence';
    const validations = new Map(observations
      .filter(observation => observation.type === 'rpki-validation')
      .map(observation => [observation.origin_asn, observation.state]));
    const origins = [...new Set(observations.map(observation => observation.origin_asn).filter(Boolean))].sort();
    const originSummary = origins.map(origin => {
      const state = validations.get(origin);
      return `${origin} · RPKI ${state ? state.replaceAll('-', ' ') : 'not recorded'}`;
    }).join(' · ');
    const routes = observations.filter(observation => observation.type === 'bgp-route');
    const routeDetails = routes.length ? `<details><summary>${routes.length.toLocaleString()} BGP route observation${routes.length === 1 ? '' : 's'}</summary>${routes.map(route => {
      const peer = `${route.peer_asn || 'unknown peer'}${route.peer_address ? ` (${route.peer_address})` : ''}`;
      const path = route.as_path ? ` · path ${route.as_path}` : '';
      const communities = route.communities ? ` · communities ${route.communities}` : '';
      return `<span>${escapeHtml(`${route.collector || 'unknown collector'} · peer ${peer}${path}${communities}`)}</span>`;
    }).join('')}</details>` : '';
    return `<div class="vhost-observations"><span>${escapeHtml(originSummary || 'Origin not recorded')}</span>${routeDetails}</div>`;
  }

  function networkObservationsFilter(headerValue, rowValue) {
    const query = String(headerValue || '').trim().toLowerCase().replaceAll('-', ' ');
    const text = (Array.isArray(rowValue) ? rowValue : []).flatMap(observation => [
      observation.type, observation.origin_asn, observation.state, observation.collector,
      observation.peer_asn, observation.peer_address, observation.as_path, observation.communities
    ]).join(' ').toLowerCase().replaceAll('-', ' ');
    return text.includes(query);
  }

  function provenanceFormatter(cell) {
    const values = Array.isArray(cell.getValue()) ? cell.getValue() : [];
    return escapeHtml(values.join(', ') || '-');
  }

  function mountResultTable(rows) {
    state.resultTable?.destroy();
    nodes.copySelected.disabled = true;
    nodes.copySelected.textContent = 'Copy selected';
    const columns = [
      {title: 'Value', field: 'value', formatter: cell => `<span class="value-cell">${escapeHtml(cell.getValue())}</span>`, minWidth: 260, widthGrow: 2, headerFilter: 'input', headerFilterFunc: columnTextFilter, headerFilterPlaceholder: 'Filter values'},
      {title: 'DNS', field: 'dns_status', formatter: dnsFormatter, width: 130, responsive: 1, headerFilter: 'input', headerFilterFunc: columnTextFilter, headerFilterPlaceholder: 'Filter DNS'},
    ];
    if (state.route === 'hostname' && rows.some(row => Array.isArray(row.observations) && row.observations.length)) {
      columns.push(
        {title: 'Virtual-host observations', field: 'observations', formatter: vhostObservationsFormatter, minWidth: 420, widthGrow: 4, variableHeight: true, headerFilter: 'input', headerFilterFunc: vhostObservationsFilter, headerFilterPlaceholder: 'Filter endpoint evidence'},
        {title: 'Sources', field: 'sources', formatter: provenanceFormatter, minWidth: 130, responsive: 2, headerFilter: 'input', headerFilterFunc: columnTextFilter},
        {title: 'Produced by', field: 'actions', formatter: provenanceFormatter, minWidth: 130, responsive: 2, headerFilter: 'input', headerFilterFunc: columnTextFilter},
      );
    }
    if (state.route === 'asn' && rows.some(row => Array.isArray(row.observations) && row.observations.length)) {
      columns.push(
        {title: 'Organization attributions', field: 'observations', formatter: asnAttributionsFormatter, minWidth: 420, widthGrow: 4, variableHeight: true, headerFilter: 'input', headerFilterFunc: asnAttributionsFilter, headerFilterPlaceholder: 'Filter organization evidence'},
        {title: 'Sources', field: 'sources', formatter: provenanceFormatter, minWidth: 130, responsive: 2, headerFilter: 'input', headerFilterFunc: columnTextFilter},
        {title: 'Produced by', field: 'actions', formatter: provenanceFormatter, minWidth: 130, responsive: 2, headerFilter: 'input', headerFilterFunc: columnTextFilter},
      );
    }
    if (state.route === 'prefix' && rows.some(row => Array.isArray(row.observations) && row.observations.length)) {
      columns.push(
        {title: 'Routing evidence', field: 'observations', formatter: networkObservationsFormatter, minWidth: 420, widthGrow: 4, variableHeight: true, headerFilter: 'input', headerFilterFunc: networkObservationsFilter, headerFilterPlaceholder: 'Filter routing evidence'},
        {title: 'Produced by', field: 'actions', formatter: provenanceFormatter, minWidth: 130, responsive: 2, headerFilter: 'input', headerFilterFunc: columnTextFilter},
      );
    }
    if (state.route === 'hostname') {
      columns.push({
        title: 'Actions', field: 'value', formatter: resultActionFormatter, headerSort: false,
        minWidth: 265, width: 265, responsive: 0, resizable: false,
        cellClick: (event, cell) => {
          const button = event.target.closest('[data-run-action]');
          if (!button) return;
          event.stopPropagation();
          queueResultAction(button.dataset.runAction, cell.getRow().getData().value, button);
        },
      });
    }
    state.resultTable = new Tabulator(nodes.resultWorkbench.querySelector('#result-grid'), {
      data: rows,
      layout: 'fitColumns',
      responsiveLayout: 'collapse',
      resizableColumnGuide: true,
      columnDefaults: {resizable: true},
      selectableRows: true,
      rowHeader: {
        formatter: 'rowSelection', titleFormatter: 'rowSelection', headerSort: false,
        width: 48, widthGrow: 0, resizable: false, frozen: true, headerHozAlign: 'center', hozAlign: 'center'
      },
      maxHeight: 590,
      placeholder: 'No results match this filter.',
      pagination: true,
      paginationMode: 'local',
      paginationSize: 15,
      paginationSizeSelector: [15, 30, 60, 120],
      paginationCounter: 'rows',
      initialSort: [{column: 'value', dir: 'asc'}],
      columns
    });
    state.resultTable.on('rowSelectionChanged', selected => {
      nodes.copySelected.disabled = selected.length === 0;
      nodes.copySelected.textContent = selected.length ? `Copy selected (${selected.length})` : 'Copy selected';
    });
  }

  function renderResults(run) {
    const focusedRoute = document.activeElement?.dataset.route;
    const groups = groupedResults();
    const total = (run.results || []).length;
    if (total) {
      nodes.resultsSummary.textContent = `${formatCount(total, 'normalized result')} across ${formatCount(groups.length, 'route')}.`;
    } else if (run.status === 'completed') {
      const emptySources = (run.source_executions || [])
        .filter(execution => execution.status === 'completed' && Number(execution.result_count || 0) === 0)
        .map(sourceName);
      let sourceSummary = 'No normalized evidence was returned.';
      if (emptySources.length === 1) sourceSummary = `${emptySources[0]} returned no normalized evidence.`;
      if (emptySources.length > 1) sourceSummary = `${emptySources.length} selected sources returned no normalized evidence.`;
      const outcomeSummary = nodes.providerOutcomeSummary.hidden ? '' : ` · ${nodes.providerOutcomeSummary.textContent}`;
      nodes.resultsSummary.textContent = `0 normalized results${outcomeSummary}.`;
      nodes.resultsEmptyTitle.textContent = 'Enumeration completed';
      nodes.resultsEmptyCopy.textContent = `${sourceSummary} The retained evidence record is ${run.evidence_status || 'not recorded'}.`;
    } else if (run.status === 'failed' || run.status === 'cancelled') {
      const evidenceStatus = run.evidence_status || 'not recorded';
      nodes.resultsSummary.textContent = '0 normalized results.';
      nodes.resultsEmptyTitle.textContent = run.status === 'failed' ? 'Enumeration failed' : 'Enumeration cancelled';
      nodes.resultsEmptyCopy.textContent = run.status === 'failed'
        ? `${run.error || 'The enumeration failed.'} The retained evidence record is ${evidenceStatus}.`
        : `The enumeration was cancelled. The retained evidence record is ${evidenceStatus}.`;
    } else {
      nodes.resultsSummary.textContent = 'Queued and running records remain visible before terminal evidence exists.';
      nodes.resultsEmptyTitle.textContent = 'No normalized evidence yet';
      nodes.resultsEmptyCopy.textContent = nodes.resultsSummary.textContent;
    }
    nodes.resultsEmpty.hidden = total > 0;
    nodes.resultWorkbench.hidden = total === 0;
    nodes.routeTabs.hidden = total === 0;
    nodes.routeOverflowCue.hidden = total === 0;
    nodes.exportJsonl.disabled = !run.evidence_status;
    nodes.copySelected.disabled = true;
    if (!total) {
      nodes.routeTabs.innerHTML = '';
      state.resultTable?.destroy();
      state.resultTable = null;
      return;
    }
    if (!groups.some(([type]) => type === state.route)) state.route = groups[0][0];
    nodes.routeTabs.innerHTML = groups.map(([type, results]) => `
      <button class="route-tab ${type === state.route ? 'active' : ''}" type="button" data-route="${escapeHtml(type)}" aria-pressed="${type === state.route}">
        ${escapeHtml(ROUTE_LABELS[type] || type)} <span class="count-badge">${results.length}</span>
      </button>`).join('');
    const rows = groups.find(([type]) => type === state.route)?.[1] || [];
    nodes.routeCount.textContent = rows.length;
    nodes.resultSearch.value = '';
    mountResultTable(rows);
    if (focusedRoute) {
      requestAnimationFrame(() => nodes.routeTabs.querySelector(`[data-route="${CSS.escape(focusedRoute)}"]`)?.focus({preventScroll: true}));
    }
  }

  function revokeScreenshots() {
    for (const url of state.screenshotUrls.values()) URL.revokeObjectURL(url);
    state.screenshotUrls.clear();
  }

  async function loadScreenshot(screenshot, frame) {
    try {
      const response = await api(screenshot.url);
      const objectUrl = URL.createObjectURL(await response.blob());
      state.screenshotUrls.set(screenshot.url, objectUrl);
      frame.innerHTML = `<img src="${escapeHtml(objectUrl)}" alt="Screenshot preview of ${escapeHtml(screenshot.target)}">`;
    } catch {
      frame.textContent = 'Preview unavailable. Reload the run to retry.';
    }
  }

  function renderScreenshots(run) {
    revokeScreenshots();
    const screenshots = run.screenshots || [];
    nodes.screenshotSection.hidden = screenshots.length === 0;
    nodes.screenshotGallery.innerHTML = screenshots.map((screenshot, index) => `
      <button class="screenshot-card" type="button" data-screenshot-index="${index}">
        <span class="screenshot-frame">Loading managed artifact…</span>
        <strong title="${escapeHtml(screenshot.target)}">${escapeHtml(screenshot.target)}</strong>
        <small>${escapeHtml(screenshot.name)}</small>
      </button>`).join('');
    screenshots.forEach((screenshot, index) => loadScreenshot(screenshot, nodes.screenshotGallery.children[index].querySelector('.screenshot-frame')));
  }

  function renderDetail(previousRun = null) {
    const run = state.detail;
    nodes.loading.hidden = true;
    nodes.empty.hidden = true;
    nodes.detail.hidden = false;
    nodes.detailTarget.textContent = run.target;
    nodes.detailRunId.textContent = run.run_id;
    nodes.statusChips.innerHTML = `${statusChip(run.status, 'Lifecycle')}${statusChip(run.evidence_status, 'Evidence')}`;
    nodes.cancel.hidden = !['queued', 'running', 'cancelling'].includes(run.status);
    nodes.cancel.disabled = run.status === 'cancelling';
    nodes.cancel.textContent = run.status === 'cancelling' ? 'Cancellation in progress' : 'Request cancellation';
    if (isTerminalStatus(run.status)) {
      nodes.detail.insertBefore(nodes.resultsSection, nodes.runFacts);
    } else {
      nodes.detail.insertBefore(nodes.resultsSection, nodes.providerDetails);
    }
    renderFacts(run);
    renderLifecycle(run);
    renderAuthorization(run);
    renderExecutions(run);
    if (!previousRun || previousRun.status !== run.status || JSON.stringify(previousRun.results) !== JSON.stringify(run.results)) {
      renderResults(run);
    }
    if (!previousRun || JSON.stringify(previousRun.screenshots) !== JSON.stringify(run.screenshots)) {
      renderScreenshots(run);
    }
    nodes.logSection.hidden = !run.log;
    nodes.logOutput.textContent = run.log || '';
  }

  async function refreshSelected() {
    if (!state.selectedId) return;
    const selectedId = state.selectedId;
    try {
      const [detailResponse, runsResponse] = await Promise.all([
        api(`/api/v1/runs/${encodeURIComponent(selectedId)}`), api('/api/v1/runs')
      ]);
      const previousDetail = state.detail;
      const previousStatus = previousDetail?.status;
      const [detail, runs] = await Promise.all([detailResponse.json(), runsResponse.json()]);
      if (state.selectedId !== selectedId) return;
      state.detail = detail;
      state.runs = runs;
      state.pollErrorShown = false;
      renderHistory();
      renderDetail(previousDetail);
      if (state.detail.status !== previousStatus) {
        if (previousStatus === 'queued') dismissToast();
        announce(`Run lifecycle is now ${state.detail.status}.`);
      }
      if (isTerminalStatus(state.detail.status)) stopPolling();
    } catch (error) {
      if (state.selectedId !== selectedId) return;
      if (!state.pollErrorShown) {
        state.pollErrorShown = true;
        toast(`Could not refresh the run: ${error.message}. Retrying automatically.`, true);
      }
    }
  }

  async function pollSelected() {
    state.pollTimer = null;
    await refreshSelected();
    if (state.selectedId && state.detail && !isTerminalStatus(state.detail.status)) {
      state.pollTimer = setTimeout(pollSelected, 1200);
    }
  }

  function startPolling() {
    stopPolling();
    state.pollTimer = setTimeout(pollSelected, 1200);
  }

  function stopPolling() {
    if (state.pollTimer) clearTimeout(state.pollTimer);
    state.pollTimer = null;
    state.pollErrorShown = false;
  }

  function renderSourceGroups(filter = '') {
    const query = filter.trim().toLowerCase();
    const groups = ['P0', 'P1', 'P2'].map(activity => [activity, state.sources.filter(source => {
      if (source.activity !== activity) return false;
      const haystack = [source.name, ...(source.capabilities || [])].join(' ').toLowerCase();
      return !query || haystack.includes(query);
    })]);
    nodes.sourceGroups.innerHTML = groups.map(([activity, sources]) => `
      <section class="source-group" data-activity="${activity}">
        <h3>${activity} · ${activity === 'P0' ? 'Passive' : activity === 'P1' ? 'DNS interaction' : 'Direct interaction'}</h3>
        ${sources.length ? sources.map(source => `
          <label class="source-choice" title="${escapeHtml((source.capabilities || []).join(', '))}">
            <input type="checkbox" value="${escapeHtml(source.name)}" ${state.selectedSources.has(source.name) ? 'checked' : ''}>
            <span>${escapeHtml(source.name)}<small>${escapeHtml((source.capabilities || []).join(', '))}</small>${credentialRequirement(source) ? `<small class="credential-note">${escapeHtml(credentialRequirement(source))}</small>` : ''}</span>
          </label>`).join('') : '<p class="source-group-empty">No matching sources.</p>'}
      </section>`).join('');
  }

  function setP0Selection(selected) {
    for (const source of state.sources.filter(source => source.activity === 'P0')) {
      if (selected) state.selectedSources.add(source.name);
      else state.selectedSources.delete(source.name);
    }
    renderSourceGroups(nodes.sourceSearch.value);
    updateActivitySummary();
    announce(selected ? 'All passive P0 sources selected.' : 'Passive P0 sources cleared.');
  }

  function selectCapability() {
    const capability = nodes.sourceCapability.value;
    if (!capability) return;
    for (const source of state.sources) {
      if ((source.capabilities || []).includes(capability)) state.selectedSources.add(source.name);
    }
    renderSourceGroups(nodes.sourceSearch.value);
    updateActivitySummary();
    announce(`Sources providing ${capability} selected.`);
  }

  function selectedActivities() {
    const activities = new Set();
    const vhost = virtualHostSelection();
    for (const source of state.sources) if (state.selectedSources.has(source.name)) activities.add(source.activity);
    for (const action of state.actions) {
      const field = nodes.newRunForm.elements[ACTION_FIELDS[action.name] || action.name.replaceAll('-', '_')];
      const selected = action.name === 'dns-recursive'
        ? Number(field?.value) > 0
        : action.name === 'vhost'
          ? vhost.selected
        : field?.checked;
      if (selected) activities.add(action.activity);
    }
    return activities;
  }

  function virtualHostSelection() {
    const endpoint = nodes.newRunForm.elements.vhost_endpoint.value.trim();
    const candidates = nodes.newRunForm.elements.vhost_candidates.value
      .split(/\r?\n/).map(value => value.trim()).filter(Boolean);
    return {
      endpoint,
      candidates,
      selected: nodes.newRunForm.elements.vhost.checked || Boolean(endpoint) || candidates.length > 0,
    };
  }

  function updateActivitySummary() {
    const activities = selectedActivities();
    nodes.activitySummary.textContent = `P0 ${activities.has('P0') ? 'selected' : 'off'} · P1 ${activities.has('P1') ? 'selected' : 'off'} · P2 ${activities.has('P2') ? 'selected' : 'off'}`;
    nodes.activitySummary.style.borderColor = activities.has('P2') ? 'var(--danger)' : activities.has('P1') ? 'var(--warning)' : 'var(--accent)';
  }

  function openNewRun() {
    nodes.newRunForm.reset();
    nodes.newRunForm.elements.limit.value = 500;
    nodes.newRunForm.elements.deadline_seconds.value = 1800;
    state.selectedSources = new Set(state.sources.some(source => source.name === 'crtsh') ? ['crtsh'] : [state.sources[0]?.name].filter(Boolean));
    nodes.sourceSearch.value = '';
    nodes.sourceCapability.value = '';
    renderSourceGroups();
    updateActivitySummary();
    openDialog(nodes.newRunDialog, '#run-target');
  }

  function openImport() {
    nodes.importForm.reset();
    nodes.fileLabel.textContent = 'Choose a JSONL or SQLite file';
    openDialog(nodes.importDialog, '#result-file');
  }

  async function focusCreatedRun(runId) {
    state.selectedId = runId;
    const runsResponse = await api('/api/v1/runs');
    state.runs = await runsResponse.json();
    renderHistory();
    const loadError = await selectRun(runId);
    if (loadError) throw loadError;
    return state.selectedId === runId && state.detail?.run_id === runId;
  }

  async function focusAcceptedRun(runId, acceptedMessage) {
    const previousSelectedId = state.selectedId;
    const previousDetail = state.detail;
    try {
      if (!await focusCreatedRun(runId)) {
        toast(`${acceptedMessage}.`);
        return false;
      }
      return true;
    } catch (error) {
      if (state.selectedId === runId) {
        state.selectedId = previousSelectedId;
        state.detail = previousDetail;
        renderHistory();
        if (previousDetail) {
          renderDetail();
          if (!isTerminalStatus(previousDetail.status)) startPolling();
        } else {
          nodes.loading.hidden = true;
          nodes.detail.hidden = true;
        }
      }
      toast(`${acceptedMessage}, but the run view could not refresh: ${error.message}. Do not submit it again; reload the page to view it.`, true);
      return false;
    }
  }

  async function queueResultAction(action, target, button) {
    const label = action === 'screenshot' ? 'Screenshot' : 'DNS brute force';
    const payload = {target, sources: [], [action]: true};
    const resolvers = state.detail?.request?.dns_resolvers;
    if (action === 'dns_brute' && Array.isArray(resolvers) && resolvers.length) {
      payload.dns_resolvers = resolvers;
    }
    setBusy(button, true, 'Starting…');
    try {
      const response = await api('/api/v1/runs', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)
      });
      const run = await response.json();
      if (await focusAcceptedRun(run.run_id, `${label} for ${target} was queued`)) {
        toast(`${label} for ${target} is ${state.detail?.status || 'submitted'}.`);
      }
    } catch (error) {
      toast(`Could not start ${label.toLowerCase()}: ${error.message}.`, true);
    } finally {
      setBusy(button, false, '');
    }
  }

  async function submitRun(event) {
    event.preventDefault();
    showFormError(nodes.newRunError, '');
    const form = new FormData(nodes.newRunForm);
    const vhost = virtualHostSelection();
    const actionSelected = state.actions.some(action => {
      const field = ACTION_FIELDS[action.name] || action.name.replaceAll('-', '_');
      if (action.name === 'dns-recursive') return Number(form.get(field)) > 0;
      if (action.name === 'vhost') return vhost.selected;
      return form.has(field);
    });
    if (!state.selectedSources.size && !actionSelected) {
      showFormError(nodes.newRunError, 'Select at least one discovery source or additional activity.');
      return;
    }
    if (!state.selectedSources.size && vhost.selected && (!vhost.endpoint || !vhost.candidates.length)) {
      showFormError(nodes.newRunError, 'Virtual-host discovery without sources requires both a literal-IP endpoint and at least one candidate hostname.');
      return;
    }
    const payload = {
      target: form.get('target'), sources: [...state.selectedSources], limit: Number(form.get('limit')),
      start: Number(form.get('start')), deadline_seconds: Number(form.get('deadline_seconds')),
      proxies: form.has('proxies'), dns_lookup: form.has('dns_lookup'), dns_resolve: form.has('dns_resolve'),
      dns_resolvers: String(form.get('dns_resolvers')).split(',').map(value => value.trim()),
      dns_recursive_depth: Number(form.get('dns_recursive_depth')),
      dns_recursive_query_limit: Number(form.get('dns_recursive_query_limit')),
      dns_recursive_runtime_seconds: Number(form.get('dns_recursive_runtime_seconds')),
      dns_brute: form.has('dns_brute'), shodan: form.has('shodan'), routeviews: form.has('routeviews'),
      screenshot: form.has('screenshot'),
      takeover: form.has('takeover'), api_scan: form.has('api_scan'),
      api_scan_paths: form.has('api_scan')
        ? String(form.get('api_scan_paths')).split(/\r?\n/).map(value => value.trim()).filter(Boolean)
        : [],
      vhost: vhost.selected,
      vhost_endpoint: vhost.endpoint,
      vhost_candidates: vhost.candidates,
      vhost_request_limit: Number(form.get('vhost_request_limit')),
      vhost_runtime_seconds: Number(form.get('vhost_runtime_seconds')),
      vhost_timeout_seconds: Number(form.get('vhost_timeout_seconds')),
      vhost_concurrency: Number(form.get('vhost_concurrency')),
      vhost_insecure: form.has('vhost_insecure')
    };
    setBusy(nodes.submitRun, true, 'Submitting…');
    try {
      const response = await api('/api/v1/runs', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)
      });
      const run = await response.json();
      closeDialog(nodes.newRunDialog);
      const focused = await focusAcceptedRun(run.run_id, `Enumeration for ${run.target} was created`);
      if (focused && state.detail?.status === 'queued') {
        toast(`Enumeration for ${run.target} is queued.`);
      }
    } catch (error) {
      showFormError(nodes.newRunError, error.message);
    } finally {
      setBusy(nodes.submitRun, false, '');
    }
  }

  async function submitImport(event) {
    event.preventDefault();
    showFormError(nodes.importError, '');
    const file = nodes.resultFile.files[0];
    if (!file) {
      showFormError(nodes.importError, 'Choose a JSONL or SQLite result file.');
      return;
    }
    const lowerName = file.name.toLowerCase();
    const fileKind = lowerName.endsWith('.jsonl') ? 'jsonl' : SQLITE_SUFFIXES.some(suffix => lowerName.endsWith(suffix)) ? 'sqlite' : null;
    if (!fileKind) {
      showFormError(nodes.importError, 'Choose a .jsonl, .sqlite, .sqlite3, or .db file.');
      return;
    }
    if (fileKind === 'jsonl' && file.size > 10 * 1024 * 1024) {
      showFormError(nodes.importError, 'JSONL file exceeds the 10 MiB limit.');
      return;
    }
    setBusy(nodes.submitImport, true, 'Importing…');
    try {
      const path = fileKind === 'jsonl' ? '/api/v1/runs/import' : '/api/v1/runs/import-database';
      const contentType = fileKind === 'jsonl' ? 'application/x-ndjson' : 'application/vnd.sqlite3';
      const response = await api(`${path}?filename=${encodeURIComponent(file.name)}`, {
        method: 'POST', headers: {'Content-Type': contentType}, body: file
      });
      const imported = await response.json();
      closeDialog(nodes.importDialog);
      if (fileKind === 'jsonl') {
        if (await focusAcceptedRun(imported.run_id, `${file.name} was imported`)) {
          toast(`Imported ${file.name} without executing discovery.`);
        }
      } else {
        const importedIds = imported.imported_run_ids || [];
        const skippedIds = imported.skipped_run_ids || [];
        const selectedId = importedIds[0] || skippedIds[0];
        if (selectedId) {
          if (!await focusAcceptedRun(selectedId, `${file.name} was imported`)) return;
        } else {
          try {
            const runsResponse = await api('/api/v1/runs');
            state.runs = await runsResponse.json();
            renderHistory();
          } catch (error) {
            toast(`${file.name} was imported, but run history could not refresh: ${error.message}. Do not import it again; reload the page to view it.`, true);
            return;
          }
        }
        toast(`Imported ${formatCount(importedIds.length, 'run')} from ${file.name}; ${skippedIds.length} already present.`);
      }
    } catch (error) {
      showFormError(nodes.importError, error.message);
    } finally {
      setBusy(nodes.submitImport, false, '');
    }
  }

  async function requestCancellation() {
    if (!state.selectedId) return;
    const selectedId = state.selectedId;
    nodes.cancel.disabled = true;
    let detail;
    try {
      const response = await api(`/api/v1/runs/${encodeURIComponent(selectedId)}/cancel`, {method: 'POST'});
      detail = await response.json();
    } catch (error) {
      if (state.selectedId !== selectedId) return;
      nodes.cancel.disabled = false;
      toast(`Could not request cancellation: ${error.message}. Refresh the run state and try again.`, true);
      return;
    }
    if (state.selectedId !== selectedId) return;
    state.detail = detail;
    renderDetail();
    if (state.detail.status === 'cancelling') startPolling();
    else stopPolling();
    try {
      const runsResponse = await api('/api/v1/runs');
      const runs = await runsResponse.json();
      if (state.selectedId !== selectedId) return;
      state.runs = runs;
      renderHistory();
    } catch (error) {
      if (state.selectedId !== selectedId) return;
      toast(`Cancellation was accepted, but run history could not refresh: ${error.message}. Do not request it again; reload the page to confirm it.`, true);
      return;
    }
    toast(state.detail.status === 'cancelled' ? 'Queued enumeration cancelled.' : 'Cancellation requested.');
  }

  async function downloadServerExport() {
    try {
      const response = await api(`/api/v1/runs/${encodeURIComponent(state.selectedId)}/export`);
      const disposition = response.headers.get('Content-Disposition') || '';
      const match = disposition.match(/filename="([^"]+)"/);
      downloadBlob(await response.blob(), match?.[1] || 'harvestview-results.jsonl');
    } catch (error) {
      toast(`Could not export results: ${error.message}. Keep the run open and try again.`, true);
    }
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const link = Object.assign(document.createElement('a'), {href: url, download: filename});
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
    toast(`Downloaded ${filename}.`);
  }

  async function copySelected() {
    const selected = state.resultTable?.getSelectedRows().map(row => row.getData()) || [];
    if (!selected.length) return;
    const text = selected.map(result => result.value).join('\n');
    try {
      await navigator.clipboard.writeText(text);
      toast(`Copied ${selected.length} selected ${ROUTE_LABELS[state.route] || state.route}.`);
    } catch {
      toast('Clipboard access was unavailable. Use the JSONL export instead.', true);
    }
  }

  function openScreenshot(index) {
    const screenshot = state.detail?.screenshots?.[index];
    const objectUrl = state.screenshotUrls.get(screenshot?.url);
    if (!screenshot || !objectUrl) {
      toast('The screenshot preview is not available. Reload the run to retry.', true);
      return;
    }
    nodes.screenshotDialogTitle.textContent = screenshot.target;
    nodes.screenshotDialogImage.src = objectUrl;
    nodes.screenshotDialogImage.alt = `Screenshot of ${screenshot.target}`;
    openDialog(nodes.screenshotDialog, '[data-close-dialog]');
  }

  nodes.themeButton.addEventListener('click', cycleTheme);
  nodes.retryWorkspace.addEventListener('click', start);
  nodes.newRunButton.addEventListener('click', openNewRun);
  nodes.importButton.addEventListener('click', openImport);
  nodes.historySearch.addEventListener('input', renderHistory);
  nodes.newRunForm.addEventListener('submit', submitRun);
  nodes.importForm.addEventListener('submit', submitImport);
  nodes.cancel.addEventListener('click', requestCancellation);
  nodes.exportJsonl.addEventListener('click', downloadServerExport);
  nodes.copySelected.addEventListener('click', copySelected);
  nodes.resultSearch.addEventListener('input', event => {
    const query = event.target.value.trim().toLowerCase();
    state.resultTable?.setFilter(row => !query || row.value.toLowerCase().includes(query));
  });
  nodes.sourceSearch.addEventListener('input', event => renderSourceGroups(event.target.value));
  nodes.selectCapability.addEventListener('click', selectCapability);
  nodes.selectP0.addEventListener('click', () => setP0Selection(true));
  nodes.clearP0.addEventListener('click', () => setP0Selection(false));
  nodes.sourceGroups.addEventListener('change', event => {
    if (!event.target.matches('input[type="checkbox"]')) return;
    if (event.target.checked) state.selectedSources.add(event.target.value);
    else state.selectedSources.delete(event.target.value);
    updateActivitySummary();
  });
  nodes.newRunForm.addEventListener('change', updateActivitySummary);
  nodes.newRunForm.addEventListener('input', event => {
    if (event.target.matches('[name="vhost_endpoint"], [name="vhost_candidates"]')) updateActivitySummary();
  });
  nodes.dnsResolverFile.addEventListener('change', async () => {
    const file = nodes.dnsResolverFile.files[0];
    if (!file) return;
    try {
      const resolvers = (await file.text()).split(/\r?\n/).map(value => value.trim()).filter(Boolean);
      nodes.dnsResolvers.value = resolvers.join(',');
      announce(`${formatCount(resolvers.length, 'resolver address')} loaded from ${file.name}.`);
    } catch {
      toast(`Could not read ${file.name}. Choose a plain text resolver file and try again.`, true);
    }
  });
  nodes.resultFile.addEventListener('change', () => {
    const file = nodes.resultFile.files[0];
    nodes.fileLabel.textContent = file ? `${file.name} · ${(file.size / 1024).toLocaleString(undefined, {maximumFractionDigits: 1})} KiB` : 'Choose a JSONL or SQLite file';
  });

  document.addEventListener('click', event => {
    const runButton = event.target.closest('[data-run-id]');
    if (runButton) selectRun(runButton.dataset.runId);
    const routeButton = event.target.closest('[data-route]');
    if (routeButton) {
      state.route = routeButton.dataset.route;
      renderResults(state.detail);
      announce(`${ROUTE_LABELS[state.route] || state.route} route selected.`);
    }
    const screenshotButton = event.target.closest('[data-screenshot-index]');
    if (screenshotButton) openScreenshot(Number(screenshotButton.dataset.screenshotIndex));
    if (event.target.closest('[data-action="new-run"]')) openNewRun();
    if (event.target.closest('[data-action="import"]')) openImport();
    const closeButton = event.target.closest('[data-close-dialog]');
    if (closeButton) closeDialog(closeButton.closest('dialog'));
  });

  for (const dialog of [nodes.newRunDialog, nodes.importDialog, nodes.screenshotDialog]) {
    dialog.addEventListener('click', event => {
      if (event.target === dialog) closeDialog(dialog);
    });
  }

  window.addEventListener('beforeunload', () => {
    stopPolling();
    revokeScreenshots();
  });

  async function start() {
    applyTheme();
    try {
      await loadWorkspace();
    } catch (error) {
      nodes.loading.hidden = true;
      nodes.workspaceErrorMessage.textContent = error.message;
      nodes.workspaceError.hidden = false;
    }
  }

  start();
})();
