const state = {
  config: null,
  modules: [],
  jobs: [],
  activeJobId: null,
  activeJob: null,
  pollTimer: null,
  tooling: null,
  selectedPhase: "all",
  viewMode: "playbook",
  moduleExecutionProfile: "fast",
  moduleSearchQuery: "",
  insightTab: "console",
  consoleHeightLocked: false
};

const $ = (selector) => document.querySelector(selector);
const LAST_TARGET_STORAGE_KEY = "lab-console-last-target-ip";
const CONSOLE_MIN_HEIGHT = 260;

function clampConsoleHeight(value) {
  const numericValue = Number(value);
  if (!Number.isFinite(numericValue)) return CONSOLE_MIN_HEIGHT;
  return Math.max(CONSOLE_MIN_HEIGHT, Math.round(numericValue));
}

function insightScrollPanels() {
  return ["#consoleOutput", "#timelineList", "#evidenceList"]
    .map((selector) => $(selector))
    .filter(Boolean);
}

function activeInsightScrollPanel() {
  if (state.insightTab === "timeline") return $("#timelineList");
  if (state.insightTab === "evidence") return $("#evidenceList");
  return $("#consoleOutput");
}

function applyInsightPanelHeight(value) {
  const height = clampConsoleHeight(value);
  insightScrollPanels().forEach((panel) => {
    panel.style.height = `${height}px`;
  });
}

function persistConsoleHeight() {
  const activePanel = activeInsightScrollPanel();
  if (!activePanel) return;
  state.consoleHeightLocked = true;
  applyInsightPanelHeight(activePanel.getBoundingClientRect().height);
}

function syncConsoleHeightToModulePane({ force = false } = {}) {
  const activePanel = activeInsightScrollPanel();
  const modulePane = document.querySelector(".module-pane");
  const insightCard = document.querySelector(".insight-card");
  if (!activePanel || !modulePane || !insightCard) return;

  if (state.consoleHeightLocked && !force) {
    return;
  }

  const activePanelRect = activePanel.getBoundingClientRect();
  const modulePaneRect = modulePane.getBoundingClientRect();
  const insightCardRect = insightCard.getBoundingClientRect();
  const desiredHeight = activePanelRect.height + (modulePaneRect.bottom - insightCardRect.bottom);
  applyInsightPanelHeight(desiredHeight);
}

function queueConsoleHeightSync(options = {}) {
  window.requestAnimationFrame(() => syncConsoleHeightToModulePane(options));
}

function bindConsoleResizeHandle() {
  let resizeIntent = false;
  const armResize = (event) => {
    const target = event.currentTarget;
    if (!target) return;
    const rect = target.getBoundingClientRect();
    resizeIntent = rect.bottom - event.clientY <= 28;
  };
  const commitResize = () => {
    if (!resizeIntent) return;
    resizeIntent = false;
    persistConsoleHeight();
  };

  insightScrollPanels().forEach((panel) => {
    panel.addEventListener("pointerdown", armResize);
  });
  window.addEventListener("pointerup", commitResize);
  window.addEventListener("mouseup", commitResize);
  window.addEventListener("resize", () => {
    if (!state.consoleHeightLocked) {
      queueConsoleHeightSync();
    }
  });
}

function showToast(message) {
  const toast = $("#toast");
  if (!toast) return;
  toast.textContent = message;
  toast.classList.add("show");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove("show"), 2200);
}

function renderInsightTabs() {
  document.querySelectorAll("[data-insight-tab]").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.insightTab === state.insightTab);
  });
  document.querySelectorAll("[data-insight-panel]").forEach((panel) => {
    panel.classList.toggle("hidden", panel.dataset.insightPanel !== state.insightTab);
  });
  queueConsoleHeightSync();
}

function requestRangePassword() {
  const modal = $("#rangePasswordModal");
  const input = $("#rangePasswordInput");
  const confirmBtn = $("#confirmRangePasswordBtn");
  const cancelBtn = $("#cancelRangePasswordBtn");
  if (!modal || !input || !confirmBtn || !cancelBtn) {
    return Promise.resolve(window.prompt("Masukkan password simpan ranges") || "");
  }

  return new Promise((resolve) => {
    const cleanup = () => {
      modal.classList.add("hidden");
      modal.setAttribute("aria-hidden", "true");
      input.value = "";
      confirmBtn.removeEventListener("click", onConfirm);
      cancelBtn.removeEventListener("click", onCancel);
      modal.removeEventListener("click", onBackdrop);
      input.removeEventListener("keydown", onKeydown);
      document.removeEventListener("keydown", onEscape);
    };

    const onConfirm = () => {
      const value = input.value;
      cleanup();
      resolve(value);
    };

    const onCancel = () => {
      cleanup();
      resolve("");
    };

    const onBackdrop = (event) => {
      if (event.target === modal) {
        onCancel();
      }
    };

    const onKeydown = (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        onConfirm();
      }
    };

    const onEscape = (event) => {
      if (event.key === "Escape") {
        onCancel();
      }
    };

    modal.classList.remove("hidden");
    modal.setAttribute("aria-hidden", "false");
    confirmBtn.addEventListener("click", onConfirm);
    cancelBtn.addEventListener("click", onCancel);
    modal.addEventListener("click", onBackdrop);
    input.addEventListener("keydown", onKeydown);
    document.addEventListener("keydown", onEscape);
    window.setTimeout(() => input.focus(), 0);
  });
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    },
    ...options
  });

  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try {
      const data = await response.json();
      message = data.detail || message;
    } catch (error) {
      // Keep fallback.
    }
    throw new Error(message);
  }

  return response.json();
}

function groupModulesByPhase(modules) {
  return modules.reduce((accumulator, module) => {
    const key = module.phase_id;
    if (!accumulator[key]) {
      accumulator[key] = {
        label: module.phase_label,
        order: module.phase_order,
        modules: []
      };
    }
    accumulator[key].modules.push(module);
    return accumulator;
  }, {});
}

function moduleUiPriority(module) {
  const priority = {
    "sensitive-file-discovery": -20,
    "read-sensitive-file": -20,
    "baseline-nikto-review": -10,
    "recon-service-scan": -10
  };
  return priority[module?.id] ?? 0;
}

function severityBadgeMarkup(key, value) {
  return `<span class="severity-pill severity-${key}">${key} ${value}</span>`;
}

function chipMarkup(items = [], className = "") {
  return items.map((item) => `<span class="${className}">${item}</span>`).join("");
}

function currentTargetValue() {
  return ($("#targetInput")?.value || "TARGET").trim() || "TARGET";
}

function persistLastTarget(value) {
  const normalized = String(value || "").trim();
  if (!normalized) return;
  localStorage.setItem(LAST_TARGET_STORAGE_KEY, normalized);
}

function restoreLastTarget() {
  const input = $("#targetInput");
  if (!input) return;
  const saved = localStorage.getItem(LAST_TARGET_STORAGE_KEY);
  if (!saved) return;
  input.value = saved;
}

function selectedModuleProfile() {
  const activeValue = $("#moduleProfileSelect")?.value;
  return ["fast", "balanced", "deep"].includes(activeValue)
    ? activeValue
    : state.moduleExecutionProfile || "fast";
}

function setModuleExecutionProfile(profile) {
  const next = ["fast", "balanced", "deep"].includes(profile) ? profile : "fast";
  state.moduleExecutionProfile = next;
  const select = $("#moduleProfileSelect");
  if (select) select.value = next;
}

function commandPreviewMarkup(commands = []) {
  const target = currentTargetValue();
  const resolved = (commands || [])
    .map((command) => String(command || "").replaceAll("TARGET", target))
    .filter(Boolean);
  if (!resolved.length) {
    return `<div class="module-command-list"><code class="module-command">No command preview</code></div>`;
  }
  return `
    <div class="module-command-list">
      ${resolved.map((command) => `<code class="module-command">${command}</code>`).join("")}
    </div>
  `;
}

function commandPreviewForModule(module) {
  const byProfile = module?.command_preview_by_profile || {};
  return byProfile[selectedModuleProfile()] || byProfile.balanced || [];
}

function executionFlowMarkup(lines = []) {
  const items = (lines || []).filter(Boolean).slice(0, 3);
  if (!items.length) {
    return `<div class="playbook-flow-list"><p class="playbook-flow-item">No execution flow preview</p></div>`;
  }
  return `
    <div class="playbook-flow-list">
      ${items.map((line) => `<p class="playbook-flow-item">${line}</p>`).join("")}
    </div>
  `;
}

function toolDetailMap(module) {
  return new Map((module.tooling_details || []).map((item) => [item.label, item]));
}

function toolingChipMarkup(module, labels, baseClass) {
  const detailMap = toolDetailMap(module);
  return labels.map((label) => {
    const detail = detailMap.get(label);
    if (!detail) return `<span class="${baseClass}">${label}</span>`;
    const stateClass = detail.installed === false
      ? "module-chip-missing"
      : detail.installed === true
        ? "module-chip-installed"
        : "module-chip-conceptual";
    const suffix = detail.installed === false
      ? " (missing)"
      : detail.kind === "conceptual"
        ? " (concept)"
        : "";
    return `<span class="${baseClass} ${stateClass}">${label}${suffix}</span>`;
  }).join("");
}

function phaseGroupsList() {
  return Object.entries(groupModulesByPhase(state.modules))
    .sort((a, b) => a[1].order - b[1].order)
    .map(([phaseId, group]) => [
      phaseId,
      {
        ...group,
        modules: [...group.modules].sort((a, b) => {
          const priorityDelta = moduleUiPriority(a) - moduleUiPriority(b);
          if (priorityDelta !== 0) return priorityDelta;
          return String(a.title || "").localeCompare(String(b.title || ""));
        })
      }
    ]);
}

function moduleMatchesSearch(module, query) {
  const needle = String(query || "").trim().toLowerCase();
  if (!needle) return true;
  const haystack = [
    module.title,
    module.description,
    module.phase_label,
    module.risk,
    module.mitre,
    module.engine,
    module.skill_level,
    module.operator_focus,
    module.simulation_stance,
    module.depth_profile,
    ...(module.tooling || []),
    ...(module.evidence || []),
    ...(module.telemetry || []),
    ...(module.allowed_checks || []),
    ...(module.preview || [])
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return haystack.includes(needle);
}

function animatePhaseSwap() {
  const groups = $("#phaseGroups");
  const bar = $("#activePhaseBar");
  if (groups) {
    groups.classList.remove("is-switching");
    void groups.offsetWidth;
    groups.classList.add("is-switching");
    window.setTimeout(() => groups.classList.remove("is-switching"), 240);
  }
  if (bar) {
    bar.classList.remove("is-switching");
    void bar.offsetWidth;
    bar.classList.add("is-switching");
    window.setTimeout(() => bar.classList.remove("is-switching"), 240);
  }
}

function setViewMode(mode) {
  state.viewMode = mode === "detail" ? "detail" : "playbook";
  document.body.dataset.viewMode = state.viewMode;
  localStorage.setItem("lab-console-view-mode", state.viewMode);
  updateViewSwitch();
  updateViewModeNote();
}

function syncModuleProfileSelect() {
  const select = $("#moduleProfileSelect");
  if (!select) return;
  select.value = selectedModuleProfile();
}

function jobExecutionProfile(job) {
  return currentRun(job)?.execution_profile
    || job?.module_runs?.find((run) => run.execution_profile)?.execution_profile
    || job?.execution_profile
    || "fast";
}

function updateViewSwitch() {
  const playbook = $("#playbookViewBtn");
  const detail = $("#detailViewBtn");
  if (!playbook || !detail) return;
  playbook.classList.toggle("active", state.viewMode === "playbook");
  detail.classList.toggle("active", state.viewMode === "detail");
}

function updateViewModeNote() {
  const note = $("#viewModeNote");
  if (!note) return;
  note.textContent = state.viewMode === "playbook"
    ? "Ringkas untuk pentester: fokus ke proses eksekusi, toolset, dan output yang diharapkan."
    : "Mode detail menampilkan deskripsi penuh, command preview, dan konteks modul yang lebih lengkap.";
}

function renderPlaybookCard(module) {
  return `
    <article class="module-card module-card-playbook">
        <div class="module-card-head">
          <div>
            <h4>${module.title}</h4>
            <div class="module-subhead">
              <span class="skill-pill">${module.skill_level}</span>
              <span class="focus-pill">${module.operator_focus}</span>
              <span class="stance-pill">${module.simulation_stance}</span>
            </div>
          </div>
        <span class="risk-pill risk-${module.risk}">${module.risk}</span>
      </div>
      <div class="module-tags">
        <span>${selectedModuleProfile()}</span>
        <span>${module.mitre}</span>
      </div>
      <div class="playbook-summary-grid">
          <div class="playbook-line">
            <strong>Depth</strong>
            <div class="module-chip-row">
              <span class="module-chip module-chip-depth">${module.depth_profile}</span>
              ${chipMarkup(module.allowed_checks, "module-chip module-chip-muted")}
            </div>
          </div>
          <div class="playbook-line">
          <strong>Tools</strong>
          <div class="module-chip-row">${toolingChipMarkup(module, module.tooling, "module-chip")}</div>
        </div>
        <div class="playbook-line">
          <strong>Evidence</strong>
          <div class="module-chip-row">${chipMarkup(module.evidence, "module-chip module-chip-soft")}</div>
        </div>
        <div class="playbook-line">
          <strong>Detect</strong>
          <div class="module-chip-row">${chipMarkup(module.telemetry, "module-chip module-chip-muted")}</div>
        </div>
        <div class="playbook-line">
          <strong>Execution Flow</strong>
          ${executionFlowMarkup(module.preview)}
        </div>
      </div>
      <div class="module-actions">
        <button class="ghost-button compact" type="button" data-preview="${module.id}">Preview</button>
        <button class="primary-button compact" type="button" data-run="${module.id}">Run</button>
      </div>
    </article>
  `;
}

function renderDetailCard(module) {
  return `
    <article class="module-card">
      <div class="module-card-head">
        <div>
          <h4>${module.title}</h4>
          <div class="module-subhead">
            <span class="skill-pill">${module.skill_level}</span>
            <span class="focus-pill">${module.operator_focus}</span>
            <span class="stance-pill">${module.simulation_stance}</span>
          </div>
        </div>
        <span class="risk-pill risk-${module.risk}">${module.risk}</span>
      </div>
      <p>${module.description}</p>
      <div class="module-tags">
        <span>${module.engine}</span>
        <span>${selectedModuleProfile()}</span>
        <span>${module.mitre}</span>
      </div>
      <div class="module-detail-block">
        <strong>Depth profile</strong>
        <div class="module-chip-row">
          <span class="module-chip module-chip-depth">${module.depth_profile}</span>
          ${chipMarkup(module.allowed_checks, "module-chip module-chip-muted")}
        </div>
      </div>
      <div class="module-detail-block">
        <strong>WSL toolset</strong>
        <div class="module-chip-row">${toolingChipMarkup(module, module.tooling, "module-chip")}</div>
      </div>
      <div class="module-detail-block">
        <strong>Evidence target</strong>
        <div class="module-chip-row">${chipMarkup(module.evidence, "module-chip module-chip-soft")}</div>
      </div>
      <div class="module-detail-block">
        <strong>Detection surface</strong>
        <div class="module-chip-row">${chipMarkup(module.telemetry, "module-chip module-chip-muted")}</div>
      </div>
      <div class="module-detail-block">
        <strong>Command preview</strong>
        ${commandPreviewMarkup(commandPreviewForModule(module))}
      </div>
      <div class="module-actions">
        <button class="ghost-button compact" type="button" data-preview="${module.id}">Preview</button>
        <button class="primary-button compact" type="button" data-run="${module.id}">Run</button>
      </div>
    </article>
  `;
}

function ensureSelectedPhase(groups) {
  if (!groups.length) {
    state.selectedPhase = "";
    return;
  }
  const exists = groups.some(([phaseId]) => phaseId === state.selectedPhase);
  if (!exists || state.selectedPhase === "all") {
    state.selectedPhase = groups[0][0];
  }
}

function renderPhaseTabs() {
  const container = $("#phaseTabs");
  if (!container) return;
  if (String(state.moduleSearchQuery || "").trim()) {
    container.innerHTML = "";
    return;
  }
  const groups = phaseGroupsList();
  ensureSelectedPhase(groups);

  container.innerHTML = groups.map(([phaseId, group]) => `
    <button class="phase-tab${phaseId === state.selectedPhase ? " active" : ""}" type="button" data-phase-tab="${phaseId}" aria-label="${String(group.order).padStart(2, "0")} ${group.label}">
      ${String(group.order).padStart(2, "0")}
    </button>
  `).join("");
}

function renderActivePhaseBar() {
  const container = $("#activePhaseBar");
  if (!container) return;
  if (String(state.moduleSearchQuery || "").trim()) {
    container.innerHTML = "";
    return;
  }
  const groups = phaseGroupsList();
  const active = groups.find(([phaseId]) => phaseId === state.selectedPhase);
  if (!active) {
    container.innerHTML = "";
    return;
  }
  const [, group] = active;
  container.innerHTML = `
    <div class="active-phase-number">${String(group.order).padStart(2, "0")}</div>
    <div class="active-phase-name">${group.label}</div>
  `;
}

function renderModules() {
  const container = $("#phaseGroups");
  if (!container) return;
  const groups = phaseGroupsList();
  ensureSelectedPhase(groups);
  renderPhaseTabs();
  renderActivePhaseBar();
  const query = String(state.moduleSearchQuery || "").trim();

  if (query) {
    const matchingGroups = groups
      .map(([phaseId, group]) => ({
        phaseId,
        group,
        modules: group.modules.filter((module) => moduleMatchesSearch(module, query))
      }))
      .filter((entry) => entry.modules.length > 0);

    if (!matchingGroups.length) {
      container.innerHTML = `
        <section class="phase-section phase-section-compact">
          <p class="empty-jobs">Tidak ada modul yang cocok dengan pencarian.</p>
        </section>
      `;
      queueConsoleHeightSync();
      return;
    }

    container.innerHTML = matchingGroups.map(({ phaseId, group, modules }) => `
      <section class="phase-section phase-section-compact" data-phase="${phaseId}">
        <div class="phase-title">
          <span>${String(group.order).padStart(2, "0")}</span>
          <h3>${group.label}</h3>
        </div>
        <div class="module-grid">
          ${modules.map((module) => state.viewMode === "playbook" ? renderPlaybookCard(module) : renderDetailCard(module)).join("")}
        </div>
      </section>
    `).join("");
    queueConsoleHeightSync();
    return;
  }

  const active = groups.find(([phaseId]) => phaseId === state.selectedPhase);

  if (!active) {
    container.innerHTML = `<p class="empty-jobs">Tidak ada modul pada tahapan yang dipilih.</p>`;
    queueConsoleHeightSync();
    return;
  }

  const [phaseId, group] = active;
  const filteredModules = group.modules.filter((module) => moduleMatchesSearch(module, state.moduleSearchQuery));
  if (!filteredModules.length) {
    container.innerHTML = `
      <section class="phase-section phase-section-compact" data-phase="${phaseId}">
        <p class="empty-jobs">Tidak ada modul yang cocok dengan pencarian pada fase ini.</p>
      </section>
    `;
    queueConsoleHeightSync();
    return;
  }
  container.innerHTML = `
    <section class="phase-section phase-section-compact" data-phase="${phaseId}">
      <div class="module-grid">
        ${filteredModules.map((module) => state.viewMode === "playbook" ? renderPlaybookCard(module) : renderDetailCard(module)).join("")}
      </div>
    </section>
  `;
  queueConsoleHeightSync();
}

function renderJobs() {
  const container = $("#jobList");
  if (!container) return;

  if (!state.jobs.length) {
    container.innerHTML = `<p class="empty-jobs">Belum ada job. Jalankan satu modul atau full simulation chain.</p>`;
    return;
  }

  container.innerHTML = state.jobs.map((job) => `
    <article class="job-item${job.id === state.activeJobId ? " active" : ""}" data-job-card="${job.id}">
      <div class="job-item-main">
        <strong>${job.scope_label}</strong>
        <span>${jobHeadline(job)}</span>
        <div class="job-item-profile-row">
          <span class="job-profile-pill">${jobExecutionProfile(job)}</span>
        </div>
        <small>${job.status} - ${job.progress}% - ${(currentRun(job)?.title || "waiting")} - ${formatJobStamp(job.created_at)}</small>
      </div>
      <div class="job-item-actions">
        <button class="ghost-button compact job-open-btn" type="button" data-job="${job.id}">Lihat hasil</button>
        ${["pending", "running", "stopping"].includes(job.status)
          ? `<button class="ghost-button compact job-stop-btn" type="button" data-stop-job="${job.id}">Stop</button>`
          : ""}
        <button class="ghost-button compact job-delete-btn" type="button" data-delete-job="${job.id}">Hapus</button>
      </div>
    </article>
  `).join("");
}

function renderConfig() {
  if (!state.config) return;
  const input = $("#allowedSubnetsInput");
  const meta = $("#configMetaLabel");
  if (input) {
    input.value = (state.config.allowed_subnets || []).join(", ");
  }
  if (meta) {
    const source = state.config.config_source || "unknown";
    const path = state.config.config_path || "-";
    meta.textContent = `${source} - ${path}`;
  }
}

function setConsoleStatus(status, label = status) {
  $("#statusLabel").textContent = label;
  $("#statusDot").dataset.state = status;
}

function formatShortTime(value) {
  if (!value) return "--:--:--";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "--:--:--";
  return date.toLocaleTimeString("id-ID", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  });
}

function formatJobStamp(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return `${date.toLocaleDateString("id-ID")} ${formatShortTime(value)}`;
}

function currentRun(job) {
  return (job?.module_runs || []).find((run) => run.status === "running")
    || (job?.module_runs || []).find((run) => run.status === "stalled")
    || null;
}

function evidenceCount(job) {
  return Array.isArray(job?.evidence) ? job.evidence.length : 0;
}

function compareJobFreshness(a, b) {
  const aTime = new Date(a?.updated_at || a?.created_at || 0).getTime();
  const bTime = new Date(b?.updated_at || b?.created_at || 0).getTime();
  return bTime - aTime;
}

function selectPreferredJobId(jobs, activeJobId = null) {
  const list = Array.isArray(jobs) ? jobs.filter(Boolean) : [];
  if (!list.length) return null;

  const activeJob = activeJobId
    ? list.find((job) => job.id === activeJobId)
    : null;
  if (activeJob) return activeJob.id;

  const jobsWithEvidence = list
    .filter((job) => evidenceCount(job) > 0)
    .sort((a, b) => {
      const evidenceDelta = evidenceCount(b) - evidenceCount(a);
      if (evidenceDelta !== 0) return evidenceDelta;
      return compareJobFreshness(a, b);
    });
  if (jobsWithEvidence.length) return jobsWithEvidence[0].id;

  const activeRuns = list
    .filter((job) => ["running", "pending", "stopping"].includes(String(job?.status || "")))
    .sort(compareJobFreshness);
  if (activeRuns.length) return activeRuns[0].id;

  return list.slice().sort(compareJobFreshness)[0].id;
}

function currentCommand(job) {
  const logs = job?.logs || [];
  for (let index = logs.length - 1; index >= 0; index -= 1) {
    const message = String(logs[index]?.message || "").trim();
    if (message.startsWith("$ ")) return message;
  }
  const run = currentRun(job);
  return run ? `Preparing ${run.title}` : "No active command";
}

function logLines(logs) {
  return (logs || []).map((entry) => {
    const stamp = entry.timestamp ? `[${formatShortTime(entry.timestamp)}]` : "";
    const sev = `[${String(entry.severity || "info").toUpperCase()}]`;
    return [stamp, sev, entry.message].filter(Boolean).join(" ");
  }).join("\n");
}

function renderSeveritySummary(summary = {}) {
  const container = $("#severitySummary");
  container.innerHTML = ["critical", "high", "medium", "low", "info"]
    .map((key) => severityBadgeMarkup(key, Number(summary[key] || 0)))
    .join("");
}

function summarizeEvidenceBySeverity(evidence = []) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const item of evidence) {
    const severity = String(item?.severity || "info").toLowerCase();
    if (!(severity in summary)) {
      summary.info += 1;
      continue;
    }
    summary[severity] += 1;
  }
  return summary;
}

function moduleById(moduleId) {
  return state.modules.find((item) => item.id === moduleId) || null;
}

function severityRank(key) {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[String(key || "info").toLowerCase()] ?? 0;
}

function resolveVisibleEvidence(job) {
  let evidenceJob = job;
  let evidence = (job?.evidence || []).slice();

  if (!evidence.length) {
    const fallbackJob = (state.jobs || [])
      .filter((entry) => entry?.id !== job?.id && evidenceCount(entry) > 0)
      .sort((a, b) => {
        const evidenceDelta = evidenceCount(b) - evidenceCount(a);
        if (evidenceDelta !== 0) return evidenceDelta;
        return compareJobFreshness(a, b);
      })[0];
    if (fallbackJob) {
      evidenceJob = fallbackJob;
      evidence = (fallbackJob.evidence || []).slice();
    }
  }

  evidence = evidence.sort((a, b) => {
    const severityDelta = severityRank(b?.severity) - severityRank(a?.severity);
    if (severityDelta !== 0) return severityDelta;
    const aTime = new Date(a?.collected_at || 0).getTime();
    const bTime = new Date(b?.collected_at || 0).getTime();
    return bTime - aTime;
  });

  return {
    evidenceJob,
    evidence,
    severitySummary: summarizeEvidenceBySeverity(evidence)
  };
}

function evidenceArtifactHighlights(item) {
  const artifacts = item?.artifacts || {};
  const severity = String(item?.severity || "info").toLowerCase();
  const highlights = [];

  const push = (text, level = severity) => {
    if (!text) return;
    highlights.push({ severity: String(level || severity).toLowerCase(), text: String(text) });
  };

  const artifactLines = (value) => String(value || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const openPorts = Array.isArray(artifacts.open_ports) ? artifacts.open_ports : [];
  for (const entry of openPorts.slice(0, 6)) {
    if (!entry?.port) continue;
    const versionPart = entry.version ? ` ${entry.version}` : "";
    push(`Open port detected: ${entry.port}/${entry.state || "tcp"} ${entry.service || "unknown"}${versionPart}`);
  }

  if (artifacts.host_alive === true) {
    push("Host aktif di jaringan", "low");
  }

  const ipAddresses = Array.isArray(artifacts.ip_addresses) ? artifacts.ip_addresses : [];
  for (const ip of ipAddresses.slice(0, 4)) {
    push(`IP target aktif: ${ip}`, "low");
  }

  const hostnames = []
    .concat(Array.isArray(artifacts.hostnames) ? artifacts.hostnames : [])
    .concat(typeof artifacts.hostname === "string" && artifacts.hostname ? [artifacts.hostname] : []);
  for (const host of hostnames.slice(0, 3)) {
    push(`Hostname/perangkat: ${host}`, "low");
  }

  const macAddresses = Array.isArray(artifacts.mac_addresses) ? artifacts.mac_addresses : [];
  for (const mac of macAddresses.slice(0, 3)) {
    push(`MAC address: ${mac}`, "low");
  }

  const vendors = Array.isArray(artifacts.vendors) ? artifacts.vendors : [];
  for (const vendor of vendors.slice(0, 3)) {
    push(`Vendor perangkat: ${vendor}`, "low");
  }

  const deviceTypes = Array.isArray(artifacts.device_types) ? artifacts.device_types : [];
  for (const device of deviceTypes.slice(0, 3)) {
    push(`Jenis perangkat: ${device}`, "low");
  }

  if (Number.isFinite(Number(artifacts.closed_count)) && Number(artifacts.closed_count) > 0) {
    push(`Port tertutup terdeteksi: ${artifacts.closed_count}`, "low");
  }
  if (Number.isFinite(Number(artifacts.filtered_count)) && Number(artifacts.filtered_count) > 0) {
    push(`Port ter-filter/firewall: ${artifacts.filtered_count}`, "medium");
  }

  if (artifacts.latency) {
    push(`Latency host: ${artifacts.latency}`, "low");
  }
  if (artifacts.network_distance) {
    push(`Network distance: ${artifacts.network_distance}`, "low");
  }

  const osGuesses = []
    .concat(Array.isArray(artifacts.os_matches) ? artifacts.os_matches : [])
    .concat(Array.isArray(artifacts.os_guess) ? artifacts.os_guess : [])
    .concat(typeof artifacts.os_guess === "string" ? [artifacts.os_guess] : []);
  for (const guess of osGuesses.slice(0, 2)) {
    push(`OS hint: ${guess}`, "medium");
  }

  const versions = Array.isArray(artifacts.service_versions) ? artifacts.service_versions : [];
  for (const version of versions.slice(0, 4)) {
    push(`Service/version: ${version}`, "medium");
  }

  const databaseServices = Array.isArray(artifacts.database_services) ? artifacts.database_services : [];
  for (const service of databaseServices.slice(0, 6)) {
    push(`Database service exposed: ${service}`, "high");
  }

  const cves = Array.isArray(artifacts.cves) ? artifacts.cves : [];
  for (const cve of cves.slice(0, 8)) {
    push(`CVE detected: ${cve}`, "high");
  }

  const subdomains = Array.isArray(artifacts.subdomains) ? artifacts.subdomains : [];
  for (const subdomain of subdomains.slice(0, 8)) {
    push(`Subdomain discovered: ${subdomain}`, "medium");
  }

  const dnsRecords = Array.isArray(artifacts.dns_records) ? artifacts.dns_records : [];
  for (const record of dnsRecords.slice(0, 8)) {
    push(`DNS record: ${record}`, "low");
  }

  const paths = Array.isArray(artifacts.paths) ? artifacts.paths : [];
  for (const path of paths.slice(0, 6)) {
    push(`Sensitive path exposed: ${path}`, severity);
  }

  const robotsPaths = Array.isArray(artifacts.robots_paths) ? artifacts.robots_paths : [];
  for (const path of robotsPaths.slice(0, 8)) {
    push(`robots.txt hint: ${path}`, "medium");
  }

  const indexedPaths = Array.isArray(artifacts.indexed_paths) ? artifacts.indexed_paths : [];
  for (const path of indexedPaths.slice(0, 8)) {
    push(`Directory indexing enabled: ${path}`, "high");
  }

  const routes = Array.isArray(artifacts.routes) ? artifacts.routes : [];
  for (const route of routes.slice(0, 8)) {
    push(`Route discovered: ${route}`, /\b401\b|\b403\b/.test(route) ? "medium" : "high");
  }

  const httpTitles = Array.isArray(artifacts.http_titles) ? artifacts.http_titles : [];
  for (const title of httpTitles.slice(0, 4)) {
    push(`HTTP title: ${title}`, "medium");
  }

  const httpHeaders = Array.isArray(artifacts.http_headers) ? artifacts.http_headers : [];
  for (const header of httpHeaders.slice(0, 6)) {
    push(`HTTP header/server info: ${header}`, "medium");
  }

  const httpMethods = Array.isArray(artifacts.http_methods) ? artifacts.http_methods : [];
  for (const method of httpMethods.slice(0, 4)) {
    push(`HTTP methods: ${method}`, /put|delete|trace/i.test(method) ? "high" : "medium");
  }

  const smbDetails = Array.isArray(artifacts.smb_details) ? artifacts.smb_details : [];
  for (const detail of smbDetails.slice(0, 6)) {
    push(`SMB/Windows detail: ${detail}`, "medium");
  }

  const tracerouteHops = Array.isArray(artifacts.traceroute_hops) ? artifacts.traceroute_hops : [];
  for (const hop of tracerouteHops.slice(0, 6)) {
    push(`Traceroute hop: ${hop}`, "low");
  }

  const firewallIndicators = Array.isArray(artifacts.firewall_indicators) ? artifacts.firewall_indicators : [];
  for (const value of firewallIndicators.slice(0, 6)) {
    push(`Firewall/ACL indicator: ${value}`, "medium");
  }

  const serviceMisconfigs = Array.isArray(artifacts.service_misconfigurations) ? artifacts.service_misconfigurations : [];
  for (const value of serviceMisconfigs.slice(0, 6)) {
    push(`Service misconfiguration: ${value}`, "high");
  }

  const sensitiveFiles = Array.isArray(artifacts.sensitive_files) ? artifacts.sensitive_files : [];
  for (const file of sensitiveFiles.slice(0, 8)) {
    push(`Sensitive file discovered: ${file}`, /id_rsa|authorized_keys|\.env|wp-config\.php|config\.php|\.pem|\.key|shadow/i.test(file) ? "critical" : "high");
  }

  const suspiciousPhpFiles = Array.isArray(artifacts.suspicious_php_files) ? artifacts.suspicious_php_files : [];
  for (const file of suspiciousPhpFiles.slice(0, 10)) {
    push(`Suspicious PHP file exposed: ${file}`, "high");
  }

  const sensitiveLines = Array.isArray(artifacts.sensitive_lines) ? artifacts.sensitive_lines : [];
  for (const line of sensitiveLines.slice(0, 8)) {
    push(`Sensitive content excerpt: ${line}`, "critical");
  }

  const redactedPreview = Array.isArray(artifacts.redacted_preview) ? artifacts.redacted_preview : [];
  for (const line of redactedPreview.slice(0, 5)) {
    push(`Redacted file preview: ${line}`, "high");
  }

  if (artifacts.file_path) {
    push(`Sensitive file path: ${artifacts.file_path}`, "high");
  }

  const httpxOutput = artifactLines(artifacts.httpx_output);
  for (const line of httpxOutput.slice(0, 3)) {
    push(`HTTP fingerprint: ${line}`, "medium");
  }

  const whatwebOutput = artifactLines(artifacts.whatweb_output);
  for (const line of whatwebOutput.slice(0, 3)) {
    push(`Web tech/version: ${line}`, "medium");
  }

  const nucleiOutput = artifactLines(artifacts.nuclei_output);
  for (const line of nucleiOutput.slice(0, 8)) {
    push(`Nuclei finding: ${line}`, /critical|high/i.test(line) ? "high" : "medium");
  }

  const nucleiStructuredGroups = [
    ["exposed_admin_panels", "Exposed admin panel", "high"],
    ["exposed_config_files", "Exposed config file", "critical"],
    ["exposed_secrets", "Exposed secret/token", "critical"],
    ["misconfigurations", "Nuclei misconfiguration", "high"],
    ["default_credential_indicators", "Default credential indicator", "high"],
    ["vulnerable_endpoints", "Vulnerable endpoint", "high"],
    ["directory_exposures", "Directory exposure", "high"],
    ["subdomain_takeover_indicators", "Subdomain takeover indicator", "high"],
    ["open_redirect_indicators", "Open redirect indicator", "medium"],
    ["cors_misconfigurations", "CORS misconfiguration", "medium"],
    ["ssrf_indicators", "SSRF indicator", "high"],
    ["sqli_indicators", "SQL injection indicator", "high"],
    ["xss_indicators", "XSS indicator", "high"],
    ["rce_indicators", "RCE indicator", "critical"],
    ["lfi_rfi_indicators", "LFI/RFI indicator", "high"],
    ["auth_bypass_indicators", "Authentication bypass indicator", "high"],
    ["information_disclosures", "Information disclosure", "medium"],
    ["technology_fingerprints", "Technology fingerprint", "medium"],
    ["cloud_exposures", "Cloud exposure", "high"],
    ["network_misconfigurations", "Network/service misconfiguration", "high"],
    ["ssl_issues", "SSL/TLS issue", "medium"],
    ["security_header_issues", "Security header issue", "medium"],
    ["vulnerable_components", "Vulnerable CMS/plugin/framework", "high"]
  ];
  for (const [key, label, level] of nucleiStructuredGroups) {
    const values = Array.isArray(artifacts[key]) ? artifacts[key] : [];
    for (const value of values.slice(0, 6)) {
      push(`${label}: ${value}`, level);
    }
  }

  const niktoFindings = []
    .concat(Array.isArray(artifacts.nikto_findings) ? artifacts.nikto_findings : [])
    .concat(artifactLines(artifacts.nikto_output));
  for (const line of niktoFindings.slice(0, 12)) {
    if (line.startsWith("+") || line.startsWith("!")) {
      push(`Nikto finding: ${line}`, /OSVDB|CVE|admin|backup|upload|exposed|outdated|interesting/i.test(line) ? "high" : "medium");
    }
  }

  const niktoGroups = [
    ["server_banners", "Web server/banner", "medium"],
    ["outdated_components", "Outdated component", "high"],
    ["sensitive_paths", "Sensitive/default path", "high"],
    ["directory_indexing", "Directory listing open", "high"],
    ["default_pages", "Default page/file", "medium"],
    ["cgi_risks", "CGI risk", "high"],
    ["http_methods", "Dangerous HTTP method", "high"],
    ["security_headers", "Missing security header", "medium"],
    ["cookie_issues", "Cookie issue", "medium"],
    ["ssl_issues", "Nikto SSL/TLS issue", "medium"],
    ["interesting_urls", "Interesting URL", "medium"],
    ["misconfigurations", "Web server misconfiguration", "high"]
  ];
  for (const [key, label, level] of niktoGroups) {
    const values = Array.isArray(artifacts[key]) ? artifacts[key] : [];
    for (const value of values.slice(0, 6)) {
      push(`${label}: ${value}`, level);
    }
  }

  const dirEntries = []
    .concat(Array.isArray(artifacts.dir_entries) ? artifacts.dir_entries : [])
    .concat(Array.isArray(artifacts.gobbuster_paths) ? artifacts.gobbuster_paths : []);
  for (const entry of dirEntries.slice(0, 10)) {
    if (entry && typeof entry === "object") {
      const path = entry.path ? `/${entry.path}` : "/";
      const status = entry.status ? ` (Status: ${entry.status})` : "";
      const redirect = entry.redirect ? ` -> ${entry.redirect}` : "";
      push(`Directory/file found: ${path}${status}${redirect}`, entry.status === 403 || entry.status === 401 ? "medium" : "high");
    } else {
      push(`Directory/file found: ${entry}`, "high");
    }
  }

  const tlsFindings = []
    .concat(Array.isArray(artifacts.tls_findings) ? artifacts.tls_findings : [])
    .concat(Array.isArray(artifacts.certificate_details) ? artifacts.certificate_details : [])
    .concat(Array.isArray(artifacts.tls_details) ? artifacts.tls_details : []);
  for (const finding of tlsFindings.slice(0, 8)) {
    push(`TLS finding: ${finding}`, /expired|weak|tls 1\.0|tls 1\.1|self-signed/i.test(finding) ? "high" : "medium");
  }

  if (artifacts.tls_version) {
    push(`TLS version: ${artifacts.tls_version}`, "medium");
  }
  if (artifacts.cipher) {
    push(`TLS cipher: ${artifacts.cipher}`, "medium");
  }

  if (artifacts.vulnerable_parameter) {
    push(`SQL injection parameter: ${artifacts.vulnerable_parameter}`, "critical");
  }

  const sqlFindings = Array.isArray(artifacts.sql_findings) ? artifacts.sql_findings : [];
  for (const finding of sqlFindings.slice(0, 8)) {
    push(`SQLMap finding: ${finding}`, /critical|dbms|payload|inject/i.test(finding) ? "critical" : "high");
  }

  const jwtFindings = Array.isArray(artifacts.jwt_findings) ? artifacts.jwt_findings : [];
  for (const finding of jwtFindings.slice(0, 8)) {
    push(`JWT finding: ${finding}`, /none|weak|signature|kid/i.test(finding) ? "high" : "medium");
  }

  const bloodhoundFindings = Array.isArray(artifacts.bloodhound_findings) ? artifacts.bloodhound_findings : [];
  for (const finding of bloodhoundFindings.slice(0, 8)) {
    push(`Lateral path insight: ${finding}`, "high");
  }

  const credentialArtifacts = [
    ["hardcoded_credentials", "Hardcoded credential"],
    ["credential_hits", "Credential hit"],
    ["credentials", "Credential exposed"],
    ["secrets", "Secret exposed"],
    ["password_hits", "Password exposure"],
    ["exposed_files", "Exposed file"],
    ["cracked_hashes", "Cracked hash"],
    ["users", "User account discovered"],
    ["john_hits", "John password hit"],
  ];
  for (const [key, label] of credentialArtifacts) {
    const values = Array.isArray(artifacts[key]) ? artifacts[key] : [];
    for (const value of values.slice(0, 5)) {
      push(`${label}: ${value}`, "high");
    }
  }

  if (artifacts.ftp_anonymous === true) {
    push("Anonymous FTP login allowed", "critical");
  }

  const ftpListing = Array.isArray(artifacts.ftp_listing) ? artifacts.ftp_listing : [];
  for (const file of ftpListing.slice(0, 10)) {
    push(`FTP file listed: ${file}`, /config|cred|backup|db|secret|sql|env/i.test(file) ? "high" : "medium");
  }

  if (artifacts.download_url) {
    push(`Downloaded from: ${artifacts.download_url}`, "medium");
  }

  if (artifacts.file_type) {
    push(`File type: ${artifacts.file_type}`, "medium");
  }

  if (artifacts.has_sensitive_data === true) {
    push("Sensitive data indicators detected in downloaded content", "critical");
  }

  const observations = Array.isArray(artifacts.http_observations) ? artifacts.http_observations : [];
  for (const value of observations.slice(0, 4)) {
    push(`HTTP observation: ${value}`, "medium");
  }

  const cookies = Array.isArray(artifacts.cookies) ? artifacts.cookies : [];
  for (const cookie of cookies.slice(0, 4)) {
    push(`Cookie observed: ${cookie}`, /secure|httponly|samesite/i.test(cookie) ? "medium" : "low");
  }

  const genericArtifactOutputs = [
    { key: "ping_result", label: "Ping result", level: "low", limit: 2 },
    { key: "nmap_output", label: "Host discovery", level: "low", limit: 4 },
    { key: "dig_output", label: "DNS output", level: "low", limit: 4 },
    { key: "dnsx_output", label: "DNSx output", level: "medium", limit: 4 },
    { key: "sslyze_output", label: "SSLyze finding", level: "medium", limit: 6 },
    { key: "sqlmap_output", label: "SQLMap finding", level: "high", limit: 6 },
    { key: "hydra_output", label: "Hydra finding", level: "high", limit: 6 },
    { key: "jwt_output", label: "JWT output", level: "medium", limit: 6 },
    { key: "bloodhound_output", label: "BloodHound finding", level: "high", limit: 6 },
    { key: "certificate", label: "Certificate detail", level: "medium", limit: 4 },
  ];
  for (const source of genericArtifactOutputs) {
    const lines = artifactLines(artifacts[source.key]);
    for (const line of lines.slice(0, source.limit)) {
      if (line.length < 3) continue;
      if (/^Nikto|^\-+$|^\d+\s+host\(s\)\s+tested/i.test(line)) continue;
      push(`${source.label}: ${line}`, /critical|vulnerable|injection|weak|exposed|found/i.test(line) ? "high" : source.level);
    }
  }

  const evidenceText = Array.isArray(item?.details) ? item.details : [];
  for (const line of evidenceText.slice(0, 20)) {
    const text = String(line || "").trim();
    if (!text) continue;
    if (/CVE-\d{4}-\d+/i.test(text)) {
      push(`CVE detected: ${text}`, "high");
    } else if (/LFI|local file inclusion|path traversal|\.\.\/|\/etc\/passwd/i.test(text)) {
      push(`LFI/path traversal indicator: ${text}`, "high");
    } else if (/missing .*header|x-frame-options|x-content-type-options|content-security-policy/i.test(text)) {
      push(`Security header issue: ${text}`, "medium");
    } else if (/password|credential|secret|api[_ -]?key|token/i.test(text)) {
      push(`Credential indicator: ${text}`, "high");
    } else if (/\/[A-Za-z0-9._\-\/]+\s+\(Status:\s*(200|204|301|302|307|401|403)\)/i.test(text)) {
      push(`Route discovered: ${text}`, /401|403/.test(text) ? "medium" : "high");
    } else if (/^\+\s+/i.test(text)) {
      push(`Scanner finding: ${text}`, /admin|backup|upload|exposed|interesting|cve/i.test(text) ? "high" : "medium");
    } else if (/\[(?:critical|high|medium|low|info)\]/i.test(text) || /\[[a-z0-9\-_/]+\]/i.test(text)) {
      push(`Template finding: ${text}`, /critical|high/i.test(text) ? "high" : "medium");
    } else if (/hardcoded|default credentials|password reuse|weak password/i.test(text)) {
      push(`Credential weakness: ${text}`, "high");
    } else if (/^\/\S+\s+\((200|204|301|302|307|401|403)\)/i.test(text)) {
      push(`Route discovered: ${text}`, /\b401\b|\b403\b/.test(text) ? "medium" : "high");
    } else if (/\/tcp\s+open|open\s+\w+/i.test(text)) {
      push(`Service exposure: ${text}`, severity);
    } else if (/Apache|nginx|IIS|OpenSSH|PHP|WordPress|Tomcat|Jetty|MySQL|PostgreSQL/i.test(text)) {
      push(`Version/technology hint: ${text}`, "medium");
    }
  }

  const unique = [];
  const seen = new Set();
  for (const entry of highlights) {
    const key = `${entry.severity}|${entry.text}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(entry);
  }
  return unique.slice(0, 40);
}

function inferDetailSeverity(text, fallback = "info") {
  const value = String(text || "");
  if (/critical|vulnerable|sql injection|credential|password|secret|token|exposed|cracked|downloadable/i.test(value)) return "critical";
  if (/cve|high|outdated|backup|admin|jwt|nikto|nuclei|route|path|subdomain/i.test(value)) return "high";
  if (/tls|ssl|cookie|http|tech|service|version|dns|medium/i.test(value)) return "medium";
  if (/info|low|host|port|status/i.test(value)) return "low";
  return fallback;
}

function evidenceRawDetailEntries(item) {
  const details = Array.isArray(item?.details) ? item.details : [];
  return details
    .map((line) => String(line || "").trim())
    .filter(Boolean)
    .slice(0, 12)
    .map((text) => ({
      severity: inferDetailSeverity(text, String(item?.severity || "info").toLowerCase()),
      text
    }));
}

function jobNseHighlights(job, limit = 2) {
  const found = [];
  const seen = new Set();
  for (const item of (job?.evidence || [])) {
    const structured = item?.artifacts?.nse_findings_structured || [];
    for (const entry of structured) {
      if (!entry?.finding) continue;
      const key = `${entry.script}|${entry.severity}|${entry.finding}`;
      if (seen.has(key)) continue;
      seen.add(key);
      found.push({
        severity: String(entry.severity || "info").toLowerCase(),
        script: entry.script || "nse",
        finding: entry.finding
      });
    }
  }
  return found
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
    .slice(0, limit);
}

function jobHeadline(job) {
  const nse = jobNseHighlights(job, 1)[0];
  if (nse) {
    return `${String(nse.severity).toUpperCase()} · nmap/${nse.script} · ${nse.finding}`;
  }
  const topEvidence = (job?.evidence || [])
    .slice()
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))[0];
  return topEvidence?.summary || (job?.scope_type === "chain" ? "Full chain assessment" : job?.target || "-");
}

function timelineEvidenceForRun(job, run) {
  return (job?.evidence || [])
    .filter((item) => item.module_id === run.module_id)
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
}

function timelineCommandsForRun(job, run, nextRun) {
  const logs = job?.logs || [];
  const startTitle = `=== [${run.phase_label}] ${run.title} ===`;
  const endTitle = nextRun ? `=== [${nextRun.phase_label}] ${nextRun.title} ===` : null;
  let capture = false;
  const commands = [];
  const seen = new Set();

  for (const entry of logs) {
    const message = String(entry?.message || "");
    if (message === startTitle) {
      capture = true;
      continue;
    }
    if (capture && endTitle && message === endTitle) {
      break;
    }
    if (!capture) continue;
    if (!message.trim().startsWith("$ ")) continue;
    if (seen.has(message)) continue;
    seen.add(message);
    commands.push(message);
  }

  return commands.slice(0, 4);
}

function normalizeCommandForTarget(command, target) {
  const safeTarget = String(target || "").trim();
  if (!safeTarget) return command;

  return String(command || "")
    .replaceAll("https://lab.local", `https://${safeTarget}`)
    .replaceAll("http://lab.local", `http://${safeTarget}`)
    .replaceAll("ssh://target", `ssh://${safeTarget}`)
    .replaceAll("target:443", `${safeTarget}:443`)
    .replaceAll("TARGET/page", `${safeTarget}/page`)
    .replaceAll("TARGET", safeTarget)
    .replaceAll(" lab.local ", ` ${safeTarget} `)
    .replaceAll("-d lab.local", `-d ${safeTarget}`)
    .replaceAll(" lab.local]", ` ${safeTarget}]`)
    .replaceAll(" lab.local", ` ${safeTarget}`);
}

function renderTimeline(job) {
  const container = $("#timelineList");
  const label = $("#timelineCountLabel");
  const runs = (job?.module_runs || []).filter((run) => {
    const status = String(run?.status || "");
    const evidenceCount = Number(run?.evidence_count || 0);
    return evidenceCount > 0 || ["running", "completed", "failed", "stalled"].includes(status);
  });
  label.textContent = `${runs.length} phases`;

  if (!runs.length) {
    container.innerHTML = `<p class="empty-jobs">Hanya modul yang sedang berjalan atau memiliki finding yang akan tampil di timeline.</p>`;
    return;
  }

  container.innerHTML = runs.map((run, index) => `
    ${(() => {
      const module = moduleById(run.module_id);
      const nextRun = runs[index + 1];
      const evidenceItems = timelineEvidenceForRun(job, run);
      const topEvidence = evidenceItems[0];
      const topNse = jobNseHighlights({ evidence: evidenceItems }, 2);
      const commands = timelineCommandsForRun(job, run, nextRun)
        .map((command) => normalizeCommandForTarget(command, job?.target));
      const toolChips = (module?.tooling || []).slice(0, 4)
        .map((tool) => `<span class="timeline-chip timeline-chip-tool">${tool}</span>`)
        .join("");
      const commandMarkup = commands.length
        ? `
          <div class="timeline-commands">
            <strong>Commands</strong>
            <div class="timeline-command-list">
              ${commands.map((command) => `<p class="timeline-command-code">${command}</p>`).join("")}
            </div>
          </div>
        `
        : ``;
      const findingMarkup = topEvidence
        ? `
          <div class="timeline-finding">
            <strong>Finding</strong>
            <p>${topEvidence.summary}</p>
            <div class="timeline-finding-meta">
              <span class="timeline-chip timeline-chip-severity severity-${topEvidence.severity}">${topEvidence.severity}</span>
              <span class="timeline-chip timeline-chip-evidence">${topEvidence.execution_profile}</span>
            </div>
            ${topNse.length ? `
              <div class="timeline-nse-list">
                ${topNse.map((entry) => `
                  <div class="timeline-nse-item severity-border-${entry.severity}">
                    <span class="severity-pill severity-${entry.severity}">${entry.severity}</span>
                    <span class="timeline-nse-text">nmap/${entry.script} · ${entry.finding}</span>
                  </div>
                `).join("")}
              </div>
            ` : ""}
          </div>
        `
        : ``;
      return `
    <article class="timeline-item-card severity-border-${run.highest_severity}">
      <div class="timeline-item-head">
        <strong>${String(index + 1).padStart(2, "0")} - ${run.phase_label}</strong>
        <span class="severity-pill severity-${run.highest_severity}">${run.highest_severity}</span>
      </div>
      <p>${run.title}</p>
      <div class="timeline-meta">
        <span>${run.status}</span>
        <span>${run.progress}%</span>
        <span>${run.execution_profile}</span>
        <span>${run.evidence_count} evidence</span>
      </div>
      <div class="timeline-tools">
        <strong>Tools</strong>
        <div class="timeline-chip-row">${toolChips || '<span class="timeline-chip timeline-chip-evidence">no tool mapped</span>'}</div>
      </div>
      ${commandMarkup}
      ${findingMarkup}
      <div class="timeline-progress">
        <div class="timeline-progress-fill" style="width:${Number(run.progress || 0)}%"></div>
      </div>
    </article>
      `;
    })()}
  `).join("");
}

function renderEvidence(job, resolved = resolveVisibleEvidence(job)) {
  const container = $("#evidenceList");
  const label = $("#evidenceCountLabel");
  const evidenceJob = resolved?.evidenceJob || job;
  const evidence = Array.isArray(resolved?.evidence) ? resolved.evidence : [];
  label.textContent = `${evidence.length} items`;

  if (!evidence.length) {
    container.innerHTML = `<p class="empty-jobs">Evidence akan muncul setelah modul mulai menghasilkan temuan.</p>`;
    return;
  }

  const fallbackNotice = evidenceJob?.id && evidenceJob.id !== job?.id
    ? `
      <article class="evidence-item severity-border-info">
        <div class="evidence-head">
          <strong>Menampilkan temuan terbaru yang tersedia</strong>
          <span class="severity-pill severity-info">info</span>
        </div>
        <p class="evidence-detail">Job yang sedang dipilih belum menghasilkan evidence. Panel ini menampilkan ${evidence.length} temuan dari ${evidenceJob.scope_label} agar finding terbaru tetap terlihat di layar.</p>
        <small>${evidenceJob.scope_label} - ${evidenceJob.phase_label || evidenceJob.status || "job"}</small>
      </article>
    `
    : "";

  const severityDetailMarkup = (entry) => {
    const text = String(entry?.text || "");
    const level = String(entry?.severity || "info").toLowerCase();
    return `
      <div class="evidence-detail-row severity-border-${level}">
        <span class="severity-pill severity-${level}">${level}</span>
        <p class="evidence-detail evidence-detail-code">${text}</p>
      </div>
    `;
  };

  const itemDetailMarkup = (item) => {
    const structured = Array.isArray(item?.artifacts?.nse_findings_structured)
      ? item.artifacts.nse_findings_structured
          .filter((entry) => entry && entry.finding)
          .slice(0, 8)
          .map((entry) => ({
            severity: entry.severity || "info",
            text: `nmap/${entry.script || "nse"} · ${entry.finding}`
          }))
      : [];
    const artifactHighlights = evidenceArtifactHighlights(item);
    const rawDetails = evidenceRawDetailEntries(item);
    const combined = [...structured, ...artifactHighlights, ...rawDetails];
    const deduped = [];
    const seen = new Set();
    for (const entry of combined) {
      const text = String(entry?.text || "").trim();
      if (!text) continue;
      const key = text.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      deduped.push({
        severity: String(entry?.severity || item?.severity || "info").toLowerCase(),
        text
      });
    }
    if (!deduped.length) {
      return `<p class="evidence-detail">Belum ada detail temuan tambahan.</p>`;
    }
    return deduped.slice(0, 40).map(severityDetailMarkup).join("");
  };

  container.innerHTML = `${fallbackNotice}${evidence.map((item) => `
    <article class="evidence-item severity-border-${item.severity}">
      <div class="evidence-head">
        <strong>${item.summary}</strong>
        <span class="severity-pill severity-${item.severity}">${item.severity}</span>
      </div>
      ${itemDetailMarkup(item)}
      <small>${item.module_title} - ${item.phase_label}</small>
    </article>
  `).join("")}`;
}

function renderJobProgress(job) {
  const progress = Number(job?.progress || 0);
  $("#jobProgressValue").textContent = `${progress}%`;
  $("#jobProgressBar").style.width = `${progress}%`;
  const hasJob = Boolean(job);
  $("#viewHtmlBtn").disabled = !hasJob;
}

function renderConsole(job) {
  const output = $("#consoleOutput");
  const activeLabel = $("#activeJobLabel");
  const commandLabel = $("#activeCommandLabel");
  if (!job) {
    state.activeJob = null;
    output.textContent = "Pilih job dari riwayat atau jalankan modul baru.";
    activeLabel.textContent = "No job selected";
    if (commandLabel) commandLabel.textContent = "No active command";
    renderSeveritySummary({});
    renderTimeline(null);
    renderEvidence(null);
    renderJobProgress(null);
    setConsoleStatus("idle", "idle");
    return;
  }

  state.activeJob = job;
  if (job.target) {
    const targetInput = $("#targetInput");
    if (targetInput) targetInput.value = job.target;
    persistLastTarget(job.target);
  }
  activeLabel.textContent = job.scope_label.includes(job.target)
    ? job.scope_label
    : `${job.scope_label} - ${job.target}`;
  if (commandLabel) commandLabel.textContent = currentCommand(job);
  output.textContent = logLines(job.logs) || "Job belum memiliki log.";
  output.scrollTop = output.scrollHeight;
  const resolvedEvidence = resolveVisibleEvidence(job);
  renderSeveritySummary(resolvedEvidence.severitySummary);
  renderTimeline(job);
  renderEvidence(job, resolvedEvidence);
  renderJobProgress(job);
  setConsoleStatus(job.status, job.status);
}

async function loadConfig() {
  state.config = await api("/api/config");
  renderConfig();
}

function readAllowedSubnets() {
  return ($("#allowedSubnetsInput").value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

async function saveAllowedSubnets() {
  try {
    const allowedSubnets = readAllowedSubnets();
    const password = await requestRangePassword();
    if (!password) {
      showToast("Simpan ranges dibatalkan.");
      return;
    }
    const result = await api("/api/config/allowed-subnets", {
      method: "POST",
      body: JSON.stringify({ allowed_subnets: allowedSubnets, password })
    });
    state.config = result.config;
    renderConfig();
    showToast(result.message || "Approved ranges berhasil disimpan.");
  } catch (error) {
    showToast(error.message);
  }
}

async function reloadConfig() {
  try {
    const result = await api("/api/config/reload", { method: "POST" });
    state.config = result.config;
    renderConfig();
    showToast(result.message || "Konfigurasi lab dimuat ulang.");
  } catch (error) {
    showToast(error.message);
  }
}

async function loadModules() {
  const result = await api("/api/modules");
  state.modules = result.modules;
  syncModuleProfileSelect();
  renderModules();
}

async function loadJobs() {
  const result = await api("/api/jobs");
  state.jobs = result.jobs;
  if (state.jobs.length) {
    state.activeJobId = selectPreferredJobId(state.jobs, state.activeJobId);
  } else {
    state.activeJobId = null;
  }
  renderJobs();
}

async function loadJob(jobId) {
  const result = await api(`/api/jobs/${jobId}`);
  state.activeJobId = result.job.id;
  renderConsole(result.job);
  renderJobs();

  const activeStates = new Set(["pending", "running"]);
  window.clearTimeout(state.pollTimer);
  if (activeStates.has(result.job.status)) {
    state.pollTimer = window.setTimeout(async () => {
      await loadJobs();
      await loadJob(jobId);
    }, 1200);
  }
}

async function deleteJob(jobId) {
  try {
    await api(`/api/jobs/${jobId}`, { method: "DELETE" });
    if (state.activeJobId === jobId) {
      state.activeJobId = null;
      renderConsole(null);
    }
    await loadJobs();
    if (state.jobs.length) {
      await loadJob(state.jobs[0].id);
    } else {
      renderConsole(null);
    }
    showToast("Job berhasil dihapus.");
  } catch (error) {
    showToast(error.message);
  }
}

async function stopJob(jobId) {
  try {
    const result = await api(`/api/jobs/${jobId}/stop`, { method: "POST" });
    showToast(result.message || "Stop request dikirim.");
    await loadJobs();
    if (state.activeJobId === jobId) {
      await loadJob(jobId);
    }
  } catch (error) {
    showToast(error.message);
  }
}

async function stopAllJobs() {
  try {
    const result = await api("/api/jobs/stop-all", { method: "POST" });
    showToast(result.message || "Stop request dikirim ke seluruh job aktif.");
    await loadJobs();
    if (state.activeJobId) {
      await loadJob(state.activeJobId);
    }
  } catch (error) {
    showToast(error.message);
  }
}

async function clearJobs() {
  try {
    await api("/api/jobs", { method: "DELETE" });
    state.activeJobId = null;
    await loadJobs();
    renderConsole(null);
    showToast("Seluruh job berhasil dihapus.");
  } catch (error) {
    showToast(error.message);
  }
}

function readTargetPayload() {
  const target = $("#targetInput").value.trim();
  persistLastTarget(target);
  return {
    target,
    note: `Phase filter: ${state.selectedPhase}`,
    execution_profile: selectedModuleProfile()
  };
}

async function runModule(moduleId) {
  try {
    const payload = readTargetPayload();
    const result = await api("/api/jobs", {
      method: "POST",
      body: JSON.stringify({
        module_id: moduleId,
        target: payload.target,
        note: payload.note,
        execution_profile: payload.execution_profile
      })
    });
    showToast("Job berhasil dibuat.");
    await loadJobs();
    await loadJob(result.job.id);
  } catch (error) {
    showToast(error.message);
  }
}

async function runFullChain() {
  try {
    const payload = readTargetPayload();
    const result = await api("/api/jobs/full-chain", {
      method: "POST",
      body: JSON.stringify({
        target: payload.target,
        note: payload.note,
        execution_profile: payload.execution_profile
      })
    });
    showToast(`Pentest IP ${payload.target} dimulai dengan profile ${payload.execution_profile}.`);
    await loadJobs();
    await loadJob(result.job.id);
  } catch (error) {
    showToast(error.message);
  }
}

async function previewModule(moduleId) {
  const module = state.modules.find((item) => item.id === moduleId);
  if (!module) return;

  const payload = readTargetPayload();
  let dryRun = null;
  try {
    const result = await api(`/api/modules/${moduleId}/dry-run?target=${encodeURIComponent(payload.target)}&note=${encodeURIComponent(payload.note)}&execution_profile=${encodeURIComponent(payload.execution_profile)}`);
    dryRun = result.dry_run;
  } catch (error) {
    showToast(error.message);
  }

  const preview = [
    `[ Preview ] ${module.title}`,
    `Fase              : ${module.phase_label}`,
    `Risk              : ${module.risk}`,
    `Skill Level       : ${module.skill_level}`,
    `Operator Focus    : ${module.operator_focus}`,
    `Sim Stance        : ${module.simulation_stance}`,
    `Depth Profile     : ${module.depth_profile}`,
    `Engine            : ${module.engine}`,
    `Mode              : ${module.mode}`,
    `Execution Profile : ${payload.execution_profile}`,
    `MITRE             : ${module.mitre}`,
    "",
    module.description,
    "",
    "Allowed Checks:",
    module.allowed_checks.map((item) => `- ${item}`).join("\n"),
    "",
    "Recommended WSL Tooling:",
    module.tooling.map((item) => `- ${item}`).join("\n"),
    "",
    "Evidence Targets:",
    module.evidence.map((item) => `- ${item}`).join("\n"),
    "",
    "Detection Surface:",
    module.telemetry.map((item) => `- ${item}`).join("\n"),
    "",
    "Resolved Commands:",
    (dryRun?.commands?.length
      ? dryRun.commands.map((item) => `${item}`).join("\n")
      : "- Tidak ada command reference untuk modul ini.").replaceAll("Â·", "·"),
    "",
    "Module Notes:",
    module.preview.join("\n")
  ].join("\n");

  $("#activeJobLabel").textContent = `${module.title} - preview`;
  $("#consoleOutput").textContent = preview;
  renderSeveritySummary({});
  renderTimeline(null);
  renderEvidence(null);
  setConsoleStatus("preview", "preview");
}

async function viewHtmlReport() {
  if (!state.activeJobId) return;
  const reportUrl = `/api/jobs/${state.activeJobId}/report.html`;
  const opened = window.open(reportUrl, "_blank", "noopener,noreferrer");
  if (!opened) {
    showToast("Popup diblokir browser. Izinkan tab baru untuk melihat report HTML.");
    return;
  }
  showToast("Report HTML dibuka di tab baru.");
}

function bindEvents() {
  $("#phaseGroups").addEventListener("click", (event) => {
    const runId = event.target.dataset.run;
    const previewId = event.target.dataset.preview;
    if (runId) runModule(runId);
    if (previewId) previewModule(previewId);
  });

  $("#jobList").addEventListener("click", (event) => {
    const stopButton = event.target.closest("[data-stop-job]");
    if (stopButton) {
      event.stopPropagation();
      stopJob(stopButton.dataset.stopJob);
      return;
    }
    const deleteButton = event.target.closest("[data-delete-job]");
    if (deleteButton) {
      event.stopPropagation();
      deleteJob(deleteButton.dataset.deleteJob);
      return;
    }
    const card = event.target.closest("[data-job-card]");
    if (card && !event.target.closest("button")) {
      loadJob(card.dataset.jobCard);
      return;
    }
    const button = event.target.closest("[data-job]");
    if (!button) return;
    loadJob(button.dataset.job);
  });

  $("#runChainBtn").addEventListener("click", runFullChain);
  $("#refreshModulesBtn").addEventListener("click", async () => {
    await loadModules();
    showToast("Catalog modul diperbarui.");
  });
  $("#reloadConfigBtn").addEventListener("click", reloadConfig);
  $("#saveRangesBtn").addEventListener("click", saveAllowedSubnets);
  $("#phaseTabs").addEventListener("click", (event) => {
    const button = event.target.closest("[data-phase-tab]");
    if (!button) return;
    if (state.selectedPhase === button.dataset.phaseTab) return;
    state.selectedPhase = button.dataset.phaseTab;
    renderModules();
    animatePhaseSwap();
  });
  $("#playbookViewBtn").addEventListener("click", () => {
    setViewMode("playbook");
    renderModules();
  });
  $("#insightTabs").addEventListener("click", (event) => {
    const button = event.target.closest("[data-insight-tab]");
    if (!button) return;
    state.insightTab = button.dataset.insightTab || "console";
    renderInsightTabs();
  });
  $("#detailViewBtn").addEventListener("click", () => {
    setViewMode("detail");
    renderModules();
    renderInsightTabs();
  });
  $("#refreshJobsBtn").addEventListener("click", async () => {
    await loadJobs();
    if (state.activeJobId) await loadJob(state.activeJobId);
  });
  $("#stopAllJobsBtn").addEventListener("click", stopAllJobs);
  $("#clearJobsBtn").addEventListener("click", clearJobs);
  $("#viewHtmlBtn").addEventListener("click", viewHtmlReport);
  $("#targetInput").addEventListener("input", () => {
    persistLastTarget($("#targetInput").value);
    renderModules();
  });
  $("#moduleSearchInput").addEventListener("input", (event) => {
    state.moduleSearchQuery = event.target.value || "";
    renderModules();
  });
  $("#moduleProfileSelect").addEventListener("change", (event) => {
    setModuleExecutionProfile(event.target.value || "fast");
    renderModules();
  });

  $("#themeToggle").addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    localStorage.setItem("lab-console-theme", next);
  });
}

function initTheme() {
  document.documentElement.dataset.theme = localStorage.getItem("lab-console-theme") || "light";
}

function initViewMode() {
  setViewMode(localStorage.getItem("lab-console-view-mode") || "playbook");
}

async function init() {
  initTheme();
  initViewMode();
  restoreLastTarget();
  setModuleExecutionProfile("fast");
  syncModuleProfileSelect();
  bindEvents();
  bindConsoleResizeHandle();
  try {
  await loadConfig();
  await loadModules();
  await loadJobs();
  renderInsightTabs();
  queueConsoleHeightSync();
    if (state.activeJobId) {
      await loadJob(state.activeJobId);
    } else {
      renderConsole(null);
    }
  } catch (error) {
    $("#consoleOutput").textContent = `Gagal memuat backend.\n\n${error.message}\n\nPastikan FastAPI sudah berjalan dari WSL.`;
    setConsoleStatus("error", "backend unavailable");
  }
}

document.addEventListener("DOMContentLoaded", init);
