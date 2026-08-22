// ============================================================
// SIDEBAR NAVIGATION
// ============================================================

document.addEventListener('DOMContentLoaded', function() {
    console.log('🛡️ CodeGuard Dashboard Loading...');
    
    const navItems = document.querySelectorAll('.nav-item');
    const sections = document.querySelectorAll('.section');
    
    function switchSection(sectionId) {
        sections.forEach(section => {
            section.classList.remove('active');
        });
        
        const targetSection = document.getElementById(sectionId);
        if (targetSection) {
            targetSection.classList.add('active');
        }
        
        navItems.forEach(item => {
            item.classList.remove('active');
            if (item.dataset.section === sectionId) {
                item.classList.add('active');
            }
        });
    }
    
    navItems.forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            const sectionId = this.dataset.section;
            if (sectionId) {
                switchSection(sectionId);
            }
        });
    });
});

// ============================================================
// DASHBOARD STATS
// ============================================================

async function loadDashboardStats() {
    try {
        const response = await fetch('/api/dashboard-stats');
        const data = await response.json();
        
        if (response.ok) {
            document.getElementById('dashScans').textContent = data.total_scans || 0;
            document.getElementById('dashScore').textContent = Math.round(data.average_score || 0);
            document.getElementById('dashCritical').textContent = data.severity_counts?.critical || 0;
            document.getElementById('dashHigh').textContent = data.severity_counts?.high || 0;
            document.getElementById('dashMedium').textContent = data.severity_counts?.medium || 0;
            document.getElementById('dashLow').textContent = data.severity_counts?.low || 0;
            
            if (typeof updateCharts === 'function') {
                updateCharts(
                    Math.round(data.average_score || 0),
                    data.severity_counts || {critical: 0, high: 0, medium: 0, low: 0}
                );
            }
        }
    } catch (error) {
        console.log('Dashboard stats not available');
    }
}

document.addEventListener('DOMContentLoaded', loadDashboardStats);

// ============================================================
// CODE SCANNER
// ============================================================

const form = document.getElementById("scanForm");
const fileInput = document.getElementById("fileInput");
const statusBox = document.getElementById("status");

if (form) {
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (!fileInput.files || !fileInput.files.length) {
            statusBox.textContent = "⚠️ Please select a file first.";
            return;
        }
        await scanFile(fileInput.files[0]);
    });
}

async function scanFile(file) {
    statusBox.textContent = `🔍 Scanning ${file.name}...`;
    document.getElementById("results").classList.add("hidden");

    const data = new FormData();
    data.append("file", file);

    try {
        const response = await fetch("/api/scan", { method: "POST", body: data });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error);

        displayResults(payload, "Code");
        statusBox.textContent = `✅ Code scan complete: ${payload.score}/100`;
        loadDashboardStats();
    } catch (error) {
        statusBox.textContent = `❌ Error: ${error.message}`;
    }
}

// ============================================================
// WEBSITE SCANNER
// ============================================================

const websiteForm = document.getElementById("websiteScanForm");
const urlInput = document.getElementById("urlInput");
const websiteStatus = document.getElementById("websiteStatus");

if (websiteForm) {
    websiteForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const url = urlInput.value.trim();
        if (!url) {
            websiteStatus.textContent = "⚠️ Please enter a URL.";
            return;
        }
        await scanWebsite(url);
    });
}

async function scanWebsite(url) {
    websiteStatus.textContent = `🌐 Scanning ${url}...`;
    document.getElementById("results").classList.add("hidden");

    const data = new FormData();
    data.append("url", url);

    try {
        const response = await fetch("/api/scan-website", { method: "POST", body: data });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error);

        displayResults(payload, "Website");
        websiteStatus.textContent = `✅ Website scan complete: ${payload.score}/100`;
        loadDashboardStats();
    } catch (error) {
        websiteStatus.textContent = `❌ Error: ${error.message}`;
    }
}

// ============================================================
// API SCANNER
// ============================================================

const apiForm = document.getElementById("apiScanForm");
const apiUrlInput = document.getElementById("apiUrlInput");
const apiMethod = document.getElementById("apiMethod");
const apiStatus = document.getElementById("apiStatus");

if (apiForm) {
    apiForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const url = apiUrlInput.value.trim();
        if (!url) {
            apiStatus.textContent = "⚠️ Please enter an API URL.";
            return;
        }
        await scanAPI(url, apiMethod.value);
    });
}

async function scanAPI(url, method) {
    apiStatus.textContent = `🔌 Scanning API ${url}...`;
    document.getElementById("results").classList.add("hidden");

    const data = new FormData();
    data.append("api_url", url);
    data.append("method", method);

    try {
        const response = await fetch("/api/scan-api", { method: "POST", body: data });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error);

        displayResults(payload, "API");
        apiStatus.textContent = `✅ API scan complete: ${payload.score}/100`;
        loadDashboardStats();
    } catch (error) {
        apiStatus.textContent = `❌ Error: ${error.message}`;
    }
}

// ============================================================
// DOCUMENT SCANNER
// ============================================================

const docForm = document.getElementById("documentScanForm");
const docInput = document.getElementById("docInput");
const docStatus = document.getElementById("docStatus");

if (docForm) {
    docForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (!docInput.files || !docInput.files.length) {
            docStatus.textContent = "⚠️ Please select a document first.";
            return;
        }
        await scanDocument(docInput.files[0]);
    });
}

async function scanDocument(file) {
    docStatus.textContent = `📄 Scanning ${file.name}...`;
    document.getElementById("results").classList.add("hidden");

    const data = new FormData();
    data.append("file", file);

    try {
        const response = await fetch("/api/scan-document", { method: "POST", body: data });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error);

        displayResults(payload, "Document");
        docStatus.textContent = `✅ Document scan complete: ${payload.score}/100`;
        loadDashboardStats();
    } catch (error) {
        docStatus.textContent = `❌ Error: ${error.message}`;
    }
}

// ============================================================
// SYSTEM SCANNER
// ============================================================

const systemForm = document.getElementById("systemScanForm");
const pathInput = document.getElementById("pathInput");
const systemStatus = document.getElementById("systemStatus");

if (systemForm) {
    systemForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const path = pathInput.value.trim();
        if (!path) {
            systemStatus.textContent = "⚠️ Please enter a directory path.";
            return;
        }
        await scanSystem(path);
    });
}

async function scanSystem(path) {
    systemStatus.textContent = `🖥️ Scanning ${path}...`;
    document.getElementById("results").classList.add("hidden");

    const data = new FormData();
    data.append("path", path);

    try {
        const response = await fetch("/api/scan-system", { method: "POST", body: data });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error);

        displayResults(payload, "System");
        systemStatus.textContent = `✅ System scan complete: ${payload.score}/100`;
        loadDashboardStats();
    } catch (error) {
        systemStatus.textContent = `❌ Error: ${error.message}`;
    }
}

// ============================================================
// DISPLAY RESULTS
// ============================================================

function displayResults(payload, type) {
    const score = payload.score || 0;
    document.getElementById("score").textContent = score;
    document.getElementById("resultCritical").textContent = payload.summary?.critical || 0;
    document.getElementById("resultHigh").textContent = payload.summary?.high || 0;
    document.getElementById("resultMedium").textContent = payload.summary?.medium || 0;
    document.getElementById("resultLow").textContent = payload.summary?.low || 0;
    document.getElementById("scanId").textContent = payload.scan_id || 0;
    document.getElementById("scanType").textContent = type || "Unknown";
    
    const circle = document.getElementById("scoreCircle");
    if (circle) {
        const circumference = 314;
        const offset = circumference - (score / 100) * circumference;
        circle.style.strokeDashoffset = offset;
        const colors = score >= 80 ? '#36d399' : score >= 60 ? '#ffb454' : score >= 40 ? '#ff8b62' : '#ff5d73';
        circle.style.stroke = colors;
    }
    
    const findingsDiv = document.getElementById("findings");
    
    if (!payload.findings || payload.findings.length === 0) {
        findingsDiv.innerHTML = `
            <div class="finding-item" style="border-color:#36d399;">
                <div class="finding-header">
                    <span class="finding-title">✅ No vulnerabilities found!</span>
                    <span class="severity-badge" style="background:#36d399; color:#0a0e17;">SAFE</span>
                </div>
                <p style="color:#8fa5bd;">Great job! ${type} appears secure.</p>
            </div>
        `;
    } else {
        findingsDiv.innerHTML = payload.findings.map(f => `
            <div class="finding-item">
                <div class="finding-header">
                    <span class="finding-title">${escapeHtml(f.title)}</span>
                    <span class="severity-badge ${f.severity.toLowerCase()}">${f.severity.toUpperCase()}</span>
                </div>
                <div class="finding-description">${escapeHtml(f.description)}</div>
                <div style="color:#8fa5bd; font-size:13px; margin:4px 0;">
                    <strong>Impact:</strong> ${escapeHtml(f.impact)}
                </div>
                <div class="finding-fix">
                    <strong>💡 Fix:</strong> ${escapeHtml(f.recommendation)}
                </div>
            </div>
        `).join('');
    }
    
    document.getElementById("results").classList.remove("hidden");
}

function escapeHtml(text) {
    if (!text) return '';
    return String(text)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
}

// ============================================================
// DRAG AND DROP
// ============================================================

const dropZone = document.getElementById('dropZone');
if (dropZone) {
    dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
    dropZone.addEventListener('dragleave', () => { dropZone.classList.remove('dragover'); });
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            const file = files[0];
            if (file.name.endsWith('.py')) {
                fileInput.files = files;
                statusBox.textContent = `📎 Selected: ${file.name}`;
            } else {
                statusBox.textContent = '⚠️ Please drop a .py file only.';
            }
        }
    });
    dropZone.addEventListener('click', () => { fileInput.click(); });
}

const docDropZone = document.getElementById('docDropZone');
if (docDropZone) {
    docDropZone.addEventListener('dragover', (e) => { e.preventDefault(); docDropZone.classList.add('dragover'); });
    docDropZone.addEventListener('dragleave', () => { docDropZone.classList.remove('dragover'); });
    docDropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        docDropZone.classList.remove('dragover');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            const file = files[0];
            const validExtensions = ['.pdf', '.docx', '.xlsx', '.txt'];
            if (validExtensions.some(ext => file.name.endsWith(ext))) {
                docInput.files = files;
                docStatus.textContent = `📎 Selected: ${file.name}`;
            } else {
                docStatus.textContent = '⚠️ Please drop a supported document.';
            }
        }
    });
    docDropZone.addEventListener('click', () => { docInput.click(); });
}

console.log('🛡️ CodeGuard loaded successfully!');