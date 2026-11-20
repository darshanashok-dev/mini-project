/**
 * Cybersecurity Awareness Platform — Frontend Application
 * Production-grade vanilla JavaScript, Fetch API, and Safe DOM manipulation.
 * Zero browser persistence: in-memory state only.
 */

(function () {
  'use strict';

  // --- State ---
  let permissionsCatalog = [];
  const selectedPermissions = new Set();
  let currentCategoryFilter = 'all';
  let currentSearchQuery = '';

  // Permission category taxonomy for clean grouping
  const PERMISSION_CATEGORIES = {
    READ_SMS: 'comm',
    SEND_SMS: 'comm',
    RECEIVE_SMS: 'comm',
    READ_CALL_LOG: 'comm',
    CALL_PHONE: 'comm',

    ACCESS_FINE_LOCATION: 'location',
    ACCESS_COARSE_LOCATION: 'location',

    CAMERA: 'media',
    RECORD_AUDIO: 'media',

    READ_CONTACTS: 'contacts',
    WRITE_CONTACTS: 'contacts',
    GET_ACCOUNTS: 'contacts',

    READ_MEDIA_IMAGES: 'files',
    READ_MEDIA_VIDEO: 'files',
    READ_MEDIA_AUDIO: 'files',

    BIND_ACCESSIBILITY_SERVICE: 'system',
    SYSTEM_ALERT_WINDOW: 'system',
    REQUEST_INSTALL_PACKAGES: 'system',
    READ_PHONE_STATE: 'system',
    POST_NOTIFICATIONS: 'system'
  };

  // Neutral metadata sensitivity mapping for selection catalog (reserving Allow/Deny/Review for evaluated results)
  const PERMISSION_SENSITIVITY = {
    BIND_ACCESSIBILITY_SERVICE: { label: 'Special access', badgeClass: 'badge-access-special' },
    SYSTEM_ALERT_WINDOW: { label: 'Special access', badgeClass: 'badge-access-special' },
    REQUEST_INSTALL_PACKAGES: { label: 'Special access', badgeClass: 'badge-access-special' },
    ACCESS_COARSE_LOCATION: { label: 'Standard access', badgeClass: 'badge-access-standard' }
  };

  // Curated demo samples for evaluation
  const DEMO_SAMPLES = {
    messages: {
      'digital-arrest': "This is Inspector Sharma from Mumbai Cyber Crime Police and CBI. A parcel addressed in your name containing 200g MDMA narcotics has been seized by Customs. A non-bailable arrest warrant has been issued against you for money laundering. You are placed under digital arrest. Stay on this Skype video call immediately in a closed room and do not tell anyone. You must transfer Rs 1,50,000 security deposit to the RBI safe verification account to clear your name or police will arrest you within 2 hours.",
      'trai-disconnect': "Dear customer, your mobile number has been found associated with illegal spam activities. TRAI and Department of Telecommunications (DoT) order immediate disconnection within 24 hours. A police case has been registered. Call the enforcement officer immediately on video call to verify your identity.",
      'bank-phishing': "SBI Alert: Your net banking account will be suspended today due to pending KYC verification. Click here immediately to update and enter your OTP and login password to prevent permanent account blocked.",
      'benign-advisory': "Security Tip from State Bank of India: Bank officials never ask for your OTP, PIN, password or CVV. Never share your OTP with anyone, even if the caller claims to be from the bank.",
      'benign-work': "Hi team, please review the sprint roadmap document before tomorrow's 10:00 AM sync in Room 4B. Thank you!"
    },
    urls: {
      'ip-host': "http://192.168.1.105/bank/secure-login.html",
      'brand-subdomain': "https://sbi.bank.account-verification-portal.xyz/login",
      'typosquat': "https://paypa1-security-check.com/update-account",
      'at-symbol': "http://google.com@phishing-target-server.net/login.php",
      'shortener': "https://bit.ly/3xY8zK9",
      'legit-url': "https://www.google.com/search?q=cybersecurity+best+practices"
    }
  };

  // --- DOM Elements ---
  const tabButtons = {
    message: document.getElementById('tab-btn-message'),
    url: document.getElementById('tab-btn-url'),
    permission: document.getElementById('tab-btn-permission')
  };

  const tabPanels = {
    message: document.getElementById('tab-message'),
    url: document.getElementById('tab-url'),
    permission: document.getElementById('tab-permission')
  };

  // Message elements
  const inputMessage = document.getElementById('input-message');
  const messageCharCount = document.getElementById('message-char-count');
  const formMessage = document.getElementById('form-message');
  const btnSubmitMessage = document.getElementById('btn-submit-message');
  const btnClearMessage = document.getElementById('btn-clear-message');
  const resultMessage = document.getElementById('result-message');

  // URL elements
  const inputUrl = document.getElementById('input-url');
  const urlCharCount = document.getElementById('url-char-count');
  const formUrl = document.getElementById('form-url');
  const btnSubmitUrl = document.getElementById('btn-submit-url');
  const btnClearUrl = document.getElementById('btn-clear-url');
  const resultUrl = document.getElementById('result-url');

  // Permission elements
  const permGrid = document.getElementById('perm-grid');
  const permSearch = document.getElementById('perm-search');
  const btnSubmitPermission = document.getElementById('btn-submit-permission');
  const resultPermission = document.getElementById('result-permission');
  const btnSelectHighRisk = document.getElementById('btn-select-high-risk');
  const btnSelectAllPerm = document.getElementById('btn-select-all-perm');
  const btnDeselectPerm = document.getElementById('btn-deselect-perm');
  const selectedPermCount = document.getElementById('selected-perm-count');
  const categoryPills = document.querySelectorAll('.cat-pill');

  // --- Application Initialization ---
  document.addEventListener('DOMContentLoaded', () => {
    setupTabNavigation();
    setupMessageAnalyzer();
    setupUrlAnalyzer();
    setupPermissionAnalyzer();
    loadPermissionsCatalog();
  });

  // --- Tab Navigation ---
  function switchTab(targetKey) {
    if (!tabButtons[targetKey] || !tabPanels[targetKey]) return;

    Object.keys(tabButtons).forEach(key => {
      const isActive = key === targetKey;
      tabButtons[key].classList.toggle('active', isActive);
      tabButtons[key].setAttribute('aria-selected', isActive ? 'true' : 'false');
      tabPanels[key].classList.toggle('active', isActive);
    });
  }

  function setupTabNavigation() {
    Object.keys(tabButtons).forEach(key => {
      tabButtons[key].addEventListener('click', () => switchTab(key));
    });
  }

  // --- Module 1: Message Analyzer ---
  function setupMessageAnalyzer() {
    inputMessage.addEventListener('input', () => {
      messageCharCount.textContent = `${inputMessage.value.length.toLocaleString()} / 10,000 characters`;
    });

    btnClearMessage.addEventListener('click', () => {
      inputMessage.value = '';
      messageCharCount.textContent = '0 / 10,000 characters';
      resultMessage.classList.add('hidden');
      resultMessage.replaceChildren();
      inputMessage.focus();
    });

    // Sample chips
    document.querySelectorAll('[data-sample]').forEach(btn => {
      btn.addEventListener('click', () => {
        const key = btn.getAttribute('data-sample');
        if (DEMO_SAMPLES.messages[key]) {
          inputMessage.value = DEMO_SAMPLES.messages[key];
          messageCharCount.textContent = `${inputMessage.value.length.toLocaleString()} / 10,000 characters`;
          inputMessage.focus();
        }
      });
    });

    formMessage.addEventListener('submit', async (e) => {
      e.preventDefault();
      const text = inputMessage.value.trim();

      if (!text) {
        showErrorBanner(resultMessage, 'Please enter or paste message text to analyze.');
        return;
      }

      setLoading(btnSubmitMessage, true);
      try {
        const response = await fetch('/api/analyze/message', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text })
        });

        if (!response.ok) {
          const errData = await response.json().catch(() => ({}));
          throw new Error(errData.error || `Server returned HTTP ${response.status}`);
        }

        const data = await response.json();

        // Privacy compliance: Clear submitted text from DOM after receiving response
        inputMessage.value = '';
        messageCharCount.textContent = '0 / 10,000 characters';

        renderAnalysisResult(resultMessage, data, 'message');
      } catch (err) {
        showErrorBanner(resultMessage, err.message || 'An error occurred during message analysis.');
      } finally {
        setLoading(btnSubmitMessage, false);
      }
    });
  }

  // --- Module 2: URL Analyzer ---
  function setupUrlAnalyzer() {
    inputUrl.addEventListener('input', () => {
      urlCharCount.textContent = `${inputUrl.value.length.toLocaleString()} / 2,048 characters`;
    });

    btnClearUrl.addEventListener('click', () => {
      inputUrl.value = '';
      urlCharCount.textContent = '0 / 2,048 characters';
      resultUrl.classList.add('hidden');
      resultUrl.replaceChildren();
      inputUrl.focus();
    });

    // Sample chips
    document.querySelectorAll('[data-sample-url]').forEach(btn => {
      btn.addEventListener('click', () => {
        const key = btn.getAttribute('data-sample-url');
        if (DEMO_SAMPLES.urls[key]) {
          inputUrl.value = DEMO_SAMPLES.urls[key];
          urlCharCount.textContent = `${inputUrl.value.length.toLocaleString()} / 2,048 characters`;
          inputUrl.focus();
        }
      });
    });

    formUrl.addEventListener('submit', async (e) => {
      e.preventDefault();
      const url = inputUrl.value.trim();

      if (!url) {
        showErrorBanner(resultUrl, 'Please enter a URL to inspect.');
        return;
      }

      setLoading(btnSubmitUrl, true);
      try {
        const response = await fetch('/api/analyze/url', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url })
        });

        if (!response.ok) {
          const errData = await response.json().catch(() => ({}));
          throw new Error(errData.error || `Server returned HTTP ${response.status}`);
        }

        const data = await response.json();

        // Privacy compliance: Clear input after analysis
        inputUrl.value = '';
        urlCharCount.textContent = '0 / 2,048 characters';

        renderAnalysisResult(resultUrl, data, 'url');
      } catch (err) {
        showErrorBanner(resultUrl, err.message || 'An error occurred during URL inspection.');
      } finally {
        setLoading(btnSubmitUrl, false);
      }
    });
  }

  // --- Module 3: Android Permission Analyzer ---
  function setupPermissionAnalyzer() {
    // Search input
    permSearch.addEventListener('input', (e) => {
      currentSearchQuery = e.target.value.toLowerCase().trim();
      filterAndRenderPermissionList();
    });

    // Category pills
    categoryPills.forEach(pill => {
      pill.addEventListener('click', () => {
        categoryPills.forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        currentCategoryFilter = pill.getAttribute('data-cat') || 'all';
        filterAndRenderPermissionList();
      });
    });

    // Bulk actions
    btnSelectHighRisk.addEventListener('click', () => {
      permissionsCatalog.forEach(p => {
        const rec = (p.recommendation || '').toUpperCase();
        if (rec === 'DENY') {
          selectedPermissions.add(p.permission);
        }
      });
      syncPermissionCheckboxes();
      updateSelectedCount();
    });

    btnSelectAllPerm.addEventListener('click', () => {
      permissionsCatalog.forEach(p => selectedPermissions.add(p.permission));
      syncPermissionCheckboxes();
      updateSelectedCount();
    });

    btnDeselectPerm.addEventListener('click', () => {
      selectedPermissions.clear();
      syncPermissionCheckboxes();
      updateSelectedCount();
      resultPermission.classList.add('hidden');
      resultPermission.replaceChildren();
    });

    // Submit handler
    btnSubmitPermission.addEventListener('click', async () => {
      if (selectedPermissions.size === 0) {
        showErrorBanner(resultPermission, 'Please select at least one permission to evaluate.');
        return;
      }

      setLoading(btnSubmitPermission, true);
      try {
        const response = await fetch('/api/permissions/check', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ permissions: Array.from(selectedPermissions) })
        });

        if (!response.ok) {
          const errData = await response.json().catch(() => ({}));
          throw new Error(errData.error || `Server returned HTTP ${response.status}`);
        }

        const data = await response.json();
        renderPermissionResult(resultPermission, data);
      } catch (err) {
        showErrorBanner(resultPermission, err.message || 'An error occurred while evaluating permissions.');
      } finally {
        setLoading(btnSubmitPermission, false);
      }
    });
  }

  async function loadPermissionsCatalog() {
    try {
      const response = await fetch('/api/permissions');
      if (!response.ok) {
        throw new Error(`Failed to load catalog (HTTP ${response.status})`);
      }
      permissionsCatalog = await response.json();
      filterAndRenderPermissionList();
    } catch (err) {
      permGrid.replaceChildren();
      const errBox = document.createElement('div');
      errBox.className = 'error-banner';
      errBox.textContent = 'Could not load permissions catalog from server. Ensure backend is running.';
      permGrid.appendChild(errBox);
    }
  }

  function filterAndRenderPermissionList() {
    permGrid.replaceChildren();

    const filtered = permissionsCatalog.filter(item => {
      // 1. Category filter
      if (currentCategoryFilter !== 'all') {
        const cat = PERMISSION_CATEGORIES[item.permission] || 'system';
        if (cat !== currentCategoryFilter) return false;
      }

      // 2. Search query filter
      if (currentSearchQuery) {
        const nameMatch = item.name.toLowerCase().includes(currentSearchQuery);
        const permMatch = item.permission.toLowerCase().includes(currentSearchQuery);
        const descMatch = (item.description || '').toLowerCase().includes(currentSearchQuery);
        return nameMatch || permMatch || descMatch;
      }

      return true;
    });

    if (filtered.length === 0) {
      const emptyBox = document.createElement('div');
      emptyBox.className = 'no-findings-box';
      emptyBox.textContent = 'No permissions match the current filter criteria.';
      permGrid.appendChild(emptyBox);
      return;
    }

    filtered.forEach(item => {
      const row = document.createElement('div');
      const isSelected = selectedPermissions.has(item.permission);
      row.className = `perm-row ${isSelected ? 'selected' : ''}`;
      row.dataset.perm = item.permission;

      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.className = 'perm-checkbox';
      checkbox.checked = isSelected;
      checkbox.setAttribute('aria-label', `Select ${item.name}`);

      const body = document.createElement('div');
      body.className = 'perm-row-body';

      const header = document.createElement('div');
      header.className = 'perm-row-header';

      const title = document.createElement('span');
      title.className = 'perm-row-title';
      title.textContent = item.name;

      const tech = document.createElement('span');
      tech.className = 'perm-row-tech';
      tech.textContent = `android.permission.${item.permission}`;

      const sensitivity = PERMISSION_SENSITIVITY[item.permission] || {
        label: 'Sensitive access',
        badgeClass: 'badge-access-sensitive'
      };
      const badge = document.createElement('span');
      badge.className = `perm-row-badge ${sensitivity.badgeClass}`;
      badge.textContent = sensitivity.label;

      header.appendChild(title);
      header.appendChild(tech);
      header.appendChild(badge);

      const desc = document.createElement('p');
      desc.className = 'perm-row-desc';
      desc.textContent = item.description || '';

      body.appendChild(header);
      body.appendChild(desc);

      row.appendChild(checkbox);
      row.appendChild(body);

      // Click to toggle
      row.addEventListener('click', (e) => {
        if (e.target !== checkbox) {
          checkbox.checked = !checkbox.checked;
        }
        if (checkbox.checked) {
          selectedPermissions.add(item.permission);
          row.classList.add('selected');
        } else {
          selectedPermissions.delete(item.permission);
          row.classList.remove('selected');
        }
        updateSelectedCount();
      });

      checkbox.addEventListener('change', () => {
        if (checkbox.checked) {
          selectedPermissions.add(item.permission);
          row.classList.add('selected');
        } else {
          selectedPermissions.delete(item.permission);
          row.classList.remove('selected');
        }
        updateSelectedCount();
      });

      permGrid.appendChild(row);
    });

    updateSelectedCount();
  }

  function syncPermissionCheckboxes() {
    document.querySelectorAll('.perm-row').forEach(row => {
      const perm = row.dataset.perm;
      const chk = row.querySelector('.perm-checkbox');
      const isSel = selectedPermissions.has(perm);
      if (chk) chk.checked = isSel;
      row.classList.toggle('selected', isSel);
    });
  }

  function updateSelectedCount() {
    if (selectedPermCount) {
      const count = selectedPermissions.size;
      selectedPermCount.textContent = `${count} ${count === 1 ? 'permission' : 'permissions'} selected`;
    }
  }

  // --- Production-Grade Result Renderer (IndigoSafe / Stripe SaaS Style) ---
  function renderAnalysisResult(container, data, type) {
    container.classList.remove('hidden');
    container.replaceChildren();

    const card = document.createElement('div');
    card.className = 'result-card';

    const riskCategory = (data.category || 'Low').toLowerCase();
    const matchedCount = data.matchedRules ? data.matchedRules.length : 0;

    // 1. KPI Metric Strip (IndigoSafe / Linear dashboard header)
    const kpiStrip = document.createElement('div');
    kpiStrip.className = 'kpi-strip';

    // KPI 1: Risk Assessment & Score
    const kpi1 = document.createElement('div');
    kpi1.className = 'kpi-card';
    const kpi1Label = document.createElement('span');
    kpi1Label.className = 'kpi-label';
    kpi1Label.textContent = 'Safety Evaluation';
    const kpi1ValRow = document.createElement('div');
    kpi1ValRow.className = 'kpi-value-row';
    const kpi1Score = document.createElement('span');
    kpi1Score.className = `kpi-score tier-${riskCategory}`;
    kpi1Score.textContent = data.score;
    const kpi1Denom = document.createElement('span');
    kpi1Denom.className = 'kpi-denom';
    kpi1Denom.textContent = '/ 100';
    kpi1ValRow.appendChild(kpi1Score);
    kpi1ValRow.appendChild(kpi1Denom);
    const kpi1Badge = document.createElement('span');
    kpi1Badge.className = `kpi-badge tier-${riskCategory}`;
    kpi1Badge.textContent = `${data.category} Risk`;
    const kpi1Sub = document.createElement('p');
    kpi1Sub.className = 'kpi-subtext';
    if (data.score === 0 || data.category === 'Low') {
      kpi1Sub.textContent = 'No standard threat indicators detected in configured rules.';
    } else if (data.category === 'Medium') {
      kpi1Sub.textContent = 'Suspicious urgency or psychological pressure detected.';
    } else {
      kpi1Sub.textContent = 'Critical threat signals detected! Aligns with scam patterns.';
    }
    kpi1.appendChild(kpi1Label);
    kpi1.appendChild(kpi1ValRow);
    kpi1.appendChild(kpi1Badge);
    kpi1.appendChild(kpi1Sub);

    // KPI 2: Active Signals
    const kpi2 = document.createElement('div');
    kpi2.className = 'kpi-card';
    const kpi2Label = document.createElement('span');
    kpi2Label.className = 'kpi-label';
    kpi2Label.textContent = 'Triggered Heuristics';
    const kpi2ValRow = document.createElement('div');
    kpi2ValRow.className = 'kpi-value-row';
    const kpi2Val = document.createElement('span');
    kpi2Val.className = 'kpi-score';
    kpi2Val.textContent = matchedCount;
    const kpi2Denom = document.createElement('span');
    kpi2Denom.className = 'kpi-denom';
    kpi2Denom.textContent = matchedCount === 1 ? 'Rule' : 'Rules';
    kpi2ValRow.appendChild(kpi2Val);
    kpi2ValRow.appendChild(kpi2Denom);
    const kpi2Badge = document.createElement('span');
    kpi2Badge.className = 'kpi-badge';
    kpi2Badge.style.backgroundColor = '#F1F5F9';
    kpi2Badge.style.color = '#475569';
    kpi2Badge.textContent = 'Deduplicated';
    const kpi2Sub = document.createElement('p');
    kpi2Sub.className = 'kpi-subtext';
    kpi2Sub.textContent = 'Weights aggregated with 100-point ceiling.';
    kpi2.appendChild(kpi2Label);
    kpi2.appendChild(kpi2ValRow);
    kpi2.appendChild(kpi2Badge);
    kpi2.appendChild(kpi2Sub);

    // KPI 3: Privacy & Execution
    const kpi3 = document.createElement('div');
    kpi3.className = 'kpi-card';
    const kpi3Label = document.createElement('span');
    kpi3Label.className = 'kpi-label';
    kpi3Label.textContent = 'Processing Isolation';
    const kpi3ValRow = document.createElement('div');
    kpi3ValRow.className = 'kpi-value-row';
    const kpi3Val = document.createElement('span');
    kpi3Val.className = 'kpi-score';
    kpi3Val.style.fontSize = '1.35rem';
    kpi3Val.style.fontWeight = '700';
    kpi3Val.style.color = '#0D9488';
    kpi3Val.textContent = 'In-Memory';
    kpi3ValRow.appendChild(kpi3Val);
    const kpi3Badge = document.createElement('span');
    kpi3Badge.className = 'kpi-badge tier-low';
    kpi3Badge.textContent = 'Verified Offline';
    const kpi3Sub = document.createElement('p');
    kpi3Sub.className = 'kpi-subtext';
    kpi3Sub.textContent = 'Zero external calls • In-memory inspection.';
    kpi3.appendChild(kpi3Label);
    kpi3.appendChild(kpi3ValRow);
    kpi3.appendChild(kpi3Badge);
    kpi3.appendChild(kpi3Sub);

    kpiStrip.appendChild(kpi1);
    kpiStrip.appendChild(kpi2);
    kpiStrip.appendChild(kpi3);
    card.appendChild(kpiStrip);

    // 2. Precision Score Meter Bar
    const meterContainer = document.createElement('div');
    meterContainer.className = 'score-meter-container';

    const meterBar = document.createElement('div');
    meterBar.className = 'score-meter-bar';

    const segLow = document.createElement('div');
    segLow.className = 'score-meter-segment meter-seg-low';
    const segMed = document.createElement('div');
    segMed.className = 'score-meter-segment meter-seg-medium';
    const segHigh = document.createElement('div');
    segHigh.className = 'score-meter-segment meter-seg-high';

    meterBar.appendChild(segLow);
    meterBar.appendChild(segMed);
    meterBar.appendChild(segHigh);

    const meterFill = document.createElement('div');
    meterFill.className = `score-meter-fill tier-${riskCategory}`;
    meterFill.style.width = `${Math.min(100, Math.max(0, data.score))}%`;
    meterBar.appendChild(meterFill);

    const meterLabels = document.createElement('div');
    meterLabels.className = 'score-meter-labels';

    const lbl0 = document.createElement('span');
    lbl0.textContent = '0 (Low Risk)';
    const lbl30 = document.createElement('span');
    lbl30.textContent = '31 (Medium Risk)';
    const lbl65 = document.createElement('span');
    lbl65.textContent = '66 (High Risk)';
    const lbl100 = document.createElement('span');
    lbl100.textContent = '100';

    meterLabels.appendChild(lbl0);
    meterLabels.appendChild(lbl30);
    meterLabels.appendChild(lbl65);
    meterLabels.appendChild(lbl100);

    meterContainer.appendChild(meterBar);
    meterContainer.appendChild(meterLabels);
    card.appendChild(meterContainer);

    // 3. Matched Threat Indicators Breakdown
    const findingsSection = document.createElement('div');
    findingsSection.className = 'findings-section';

    const findingsTitle = document.createElement('h3');
    findingsTitle.className = 'findings-title';
    findingsTitle.textContent = `Evidence & Matched Heuristics (${matchedCount})`;
    findingsSection.appendChild(findingsTitle);

    if (matchedCount === 0) {
      const noFindings = document.createElement('div');
      noFindings.className = 'no-findings-box';
      noFindings.textContent = 'No heuristic detection rules triggered for this submission.';
      findingsSection.appendChild(noFindings);
    } else {
      const findingsList = document.createElement('div');
      findingsList.className = 'findings-list';

      data.matchedRules.forEach(rule => {
        const row = document.createElement('div');
        row.className = 'finding-row';

        const rowHeader = document.createElement('div');
        rowHeader.className = 'finding-header';

        const titleGroup = document.createElement('div');
        titleGroup.className = 'finding-title-group';

        const name = document.createElement('span');
        name.className = 'finding-name';
        name.textContent = rule.name;

        const idCode = document.createElement('span');
        idCode.className = 'finding-id';
        idCode.textContent = rule.id;

        titleGroup.appendChild(name);
        titleGroup.appendChild(idCode);

        const weight = document.createElement('span');
        weight.className = 'finding-weight';
        weight.textContent = `+${rule.weight} pts`;

        rowHeader.appendChild(titleGroup);
        rowHeader.appendChild(weight);
        row.appendChild(rowHeader);

        if (rule.matchedText) {
          const evidence = document.createElement('div');
          evidence.className = 'finding-evidence';
          evidence.textContent = `Evidence: "${rule.matchedText}"`;
          row.appendChild(evidence);
        }

        const expl = document.createElement('p');
        expl.className = 'finding-explanation';
        expl.textContent = rule.explanation;
        row.appendChild(expl);

        findingsList.appendChild(row);
      });

      findingsSection.appendChild(findingsList);
    }

    card.appendChild(findingsSection);

    // 4. Action & Tip Callout Cards
    if (data.recommendedAction) {
      const actionBox = document.createElement('div');
      actionBox.className = 'guidance-box action';

      const icon = document.createElement('div');
      icon.className = 'guidance-icon';
      icon.textContent = '→';

      const content = document.createElement('div');
      content.className = 'guidance-content';

      const strong = document.createElement('strong');
      strong.textContent = 'Recommended Precautionary Action';
      const text = document.createElement('span');
      text.textContent = data.recommendedAction;

      content.appendChild(strong);
      content.appendChild(text);
      actionBox.appendChild(icon);
      actionBox.appendChild(content);
      card.appendChild(actionBox);
    }

    if (data.safeHandlingTip) {
      const tipBox = document.createElement('div');
      tipBox.className = 'guidance-box tip';

      const icon = document.createElement('div');
      icon.className = 'guidance-icon';
      icon.textContent = 'ℹ';

      const content = document.createElement('div');
      content.className = 'guidance-content';

      const strong = document.createElement('strong');
      strong.textContent = 'Security Hygiene Guidance';
      const text = document.createElement('span');
      text.textContent = data.safeHandlingTip;

      content.appendChild(strong);
      content.appendChild(text);
      tipBox.appendChild(icon);
      tipBox.appendChild(content);
      card.appendChild(tipBox);
    }

    // 5. Advisory Disclaimer
    const disclaimer = document.createElement('div');
    disclaimer.className = 'disclaimer-box';
    disclaimer.textContent = data.disclaimer || 'Advisory notice: This result is deterministic heuristic guidance and does not prove that a message or URL is malicious or safe.';
    card.appendChild(disclaimer);

    container.appendChild(card);
    container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // --- Render Permission Guidance Results (KPI Header & Grouped Cards) ---
  function renderPermissionResult(container, data) {
    container.classList.remove('hidden');
    container.replaceChildren();

    const card = document.createElement('div');
    card.className = 'result-card';

    const results = data.results || [];
    let denyCount = 0;
    let reviewCount = 0;
    let allowCount = 0;

    results.forEach(r => {
      const rec = (r.recommendation || 'REVIEW').toUpperCase();
      if (rec === 'DENY') denyCount++;
      else if (rec === 'ALLOW') allowCount++;
      else reviewCount++;
    });

    // Permission KPI Strip
    const kpiStrip = document.createElement('div');
    kpiStrip.className = 'kpi-strip';

    // Total Requested
    const kpi1 = document.createElement('div');
    kpi1.className = 'kpi-card';
    const kpi1Label = document.createElement('span');
    kpi1Label.className = 'kpi-label';
    kpi1Label.textContent = 'Total Evaluated';
    const kpi1ValRow = document.createElement('div');
    kpi1ValRow.className = 'kpi-value-row';
    const kpi1Val = document.createElement('span');
    kpi1Val.className = 'kpi-score';
    kpi1Val.textContent = results.length;
    const kpi1Denom = document.createElement('span');
    kpi1Denom.className = 'kpi-denom';
    kpi1Denom.textContent = results.length === 1 ? 'Permission' : 'Permissions';
    kpi1ValRow.appendChild(kpi1Val);
    kpi1ValRow.appendChild(kpi1Denom);
    kpi1.appendChild(kpi1Label);
    kpi1.appendChild(kpi1ValRow);

    // Deny Count
    const kpi2 = document.createElement('div');
    kpi2.className = 'kpi-card';
    const kpi2Label = document.createElement('span');
    kpi2Label.className = 'kpi-label';
    kpi2Label.textContent = 'High-Risk Denials';
    const kpi2ValRow = document.createElement('div');
    kpi2ValRow.className = 'kpi-value-row';
    const kpi2Val = document.createElement('span');
    kpi2Val.className = 'kpi-score tier-high';
    kpi2Val.textContent = denyCount;
    const kpi2Badge = document.createElement('span');
    kpi2Badge.className = 'kpi-badge tier-high';
    kpi2Badge.textContent = 'Deny Recommended';
    kpi2ValRow.appendChild(kpi2Val);
    kpi2ValRow.appendChild(kpi2Badge);
    kpi2.appendChild(kpi2Label);
    kpi2.appendChild(kpi2ValRow);

    // Review Count
    const kpi3 = document.createElement('div');
    kpi3.className = 'kpi-card';
    const kpi3Label = document.createElement('span');
    kpi3Label.className = 'kpi-label';
    kpi3Label.textContent = 'Contextual Review';
    const kpi3ValRow = document.createElement('div');
    kpi3ValRow.className = 'kpi-value-row';
    const kpi3Val = document.createElement('span');
    kpi3Val.className = 'kpi-score tier-medium';
    kpi3Val.textContent = reviewCount;
    const kpi3Badge = document.createElement('span');
    kpi3Badge.className = 'kpi-badge tier-medium';
    kpi3Badge.textContent = 'Context Dependent';
    kpi3ValRow.appendChild(kpi3Val);
    kpi3ValRow.appendChild(kpi3Badge);
    kpi3.appendChild(kpi3Label);
    kpi3.appendChild(kpi3ValRow);

    kpiStrip.appendChild(kpi1);
    kpiStrip.appendChild(kpi2);
    kpiStrip.appendChild(kpi3);
    card.appendChild(kpiStrip);

    // List of permission recommendations
    const list = document.createElement('div');
    list.className = 'perm-result-list';

    results.forEach(item => {
      const rec = (item.recommendation || 'REVIEW').toUpperCase();
      const recClass = `rec-${rec.toLowerCase()}`;

      const resCard = document.createElement('div');
      resCard.className = `perm-result-card ${recClass}`;

      const resHeader = document.createElement('div');
      resHeader.className = 'perm-res-header';

      const titleGroup = document.createElement('div');
      const name = document.createElement('span');
      name.className = 'perm-res-title';
      name.textContent = item.name;

      const tech = document.createElement('span');
      tech.className = 'perm-res-tech';
      tech.textContent = `android.permission.${item.permission}`;

      titleGroup.appendChild(name);
      titleGroup.appendChild(tech);

      const badge = document.createElement('span');
      badge.className = `rec-badge badge-${rec.toLowerCase()}`;
      badge.textContent = rec;

      resHeader.appendChild(titleGroup);
      resHeader.appendChild(badge);
      resCard.appendChild(resHeader);

      // Explanation
      const explField = document.createElement('div');
      explField.className = 'perm-res-field';
      const explLabel = document.createElement('span');
      explLabel.className = 'perm-field-label';
      explLabel.textContent = 'Assessment & Guidance';
      const explText = document.createElement('p');
      explText.className = 'perm-field-text';
      explText.textContent = item.explanation;
      explField.appendChild(explLabel);
      explField.appendChild(explText);
      resCard.appendChild(explField);

      // Common legitimate use
      if (item.commonLegitimateUse) {
        const useField = document.createElement('div');
        useField.className = 'perm-res-field';
        const useLabel = document.createElement('span');
        useLabel.className = 'perm-field-label';
        useLabel.textContent = 'Common Legitimate Purpose';
        const useText = document.createElement('p');
        useText.className = 'perm-field-text';
        useText.textContent = item.commonLegitimateUse;
        useField.appendChild(useLabel);
        useField.appendChild(useText);
        resCard.appendChild(useField);
      }

      // Security risk
      if (item.securityRisk) {
        const riskField = document.createElement('div');
        riskField.className = 'perm-res-field';
        const riskLabel = document.createElement('span');
        riskLabel.className = 'perm-field-label';
        riskLabel.textContent = 'Potential Privacy / Security Risk';
        const riskText = document.createElement('p');
        riskText.className = 'perm-field-text';
        riskText.textContent = item.securityRisk;
        riskField.appendChild(riskLabel);
        riskField.appendChild(riskText);
        resCard.appendChild(riskField);
      }

      list.appendChild(resCard);
    });

    card.appendChild(list);

    // Mandatory educational warning
    const warnBox = document.createElement('div');
    warnBox.className = 'disclaimer-box';
    warnBox.textContent = data.mandatoryWarning || 'Permissions alone never prove that an application is malware. Evaluate permissions in the context of the application\'s intended functionality, developer and source.';
    card.appendChild(warnBox);

    container.appendChild(card);
    container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // --- Utility Functions ---
  function setLoading(btn, isLoading) {
    if (isLoading) {
      btn.classList.add('loading');
      btn.disabled = true;
    } else {
      btn.classList.remove('loading');
      btn.disabled = false;
    }
  }

  function showErrorBanner(container, message) {
    container.classList.remove('hidden');
    container.replaceChildren();

    const banner = document.createElement('div');
    banner.className = 'error-banner';

    const text = document.createElement('span');
    text.textContent = message;
    banner.appendChild(text);

    container.appendChild(banner);
  }

})();
