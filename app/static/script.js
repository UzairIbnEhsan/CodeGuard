/**
 * SCRIPT.JS - Frontend JavaScript
 * ==============================
 * Handles form submission, API calls, and UI updates.
 * 
 * COMMANDS TO TEST:
 * -----------------
 * # Test in browser console:
 * document.getElementById('fileInput').click()
 * 
 * # Check API response:
 * fetch('/api/scan').then(r=>r.json()).then(console.log)
 * 
 * # Clear results:
 * document.getElementById('results').classList.add('hidden')
 */

// ============================================================
// DOM ELEMENTS
// ============================================================

const form = document.getElementById("scanForm");
const input = document.getElementById("fileInput");
const statusBox = document.getElementById("status");
const results = document.getElementById("results");

// ============================================================
// HELPER: Escape HTML to prevent XSS
// ============================================================

function esc(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

// ============================================================
// RENDER FINDINGS
// ============================================================

function renderFindings(findings) {
    const box = document.getElementById("findings");
    
    if (!findings || findings.length === 0) {
        box.innerHTML = `
            <div class="finding" style="border-color:#36d399;">
                <h3 style="color:#36d399;">✅ No supported vulnerabilities detected</h3>
                <p style="color:#8fa5bd;">CodeGuard did not detect any of the current MVP security patterns.</p>
                <p style="color:#8fa5bd;font-size:13px;">
                    💡 This code appears secure! Continue following security best practices.
                </p>
            </div>`;
        return;
    }

    box.innerHTML = findings.map(f => `
        <article class="finding">
            <div class="finding-head">
                <div>
                    <h3 style="margin:0;">${esc(f.title)}</h3>
                    <div class="muted" style="color:#8fa5bd;font-size:14px;">
                        ${esc(f.category)} · ${esc(f.file)} · line ${esc(f.line)}
                    </div>
                </div>
                <div class="severity sev-${f.severity.toLowerCase()}">
                    ${esc(f.severity.toUpperCase())}
                </div>
            </div>
            <p style="margin:12px 0 4px 0;">
                <strong>What we found:</strong> ${esc(f.description)}
            </p>
            <p style="margin:4px 0;">
                <strong>Potential impact:</strong> ${esc(f.impact)}
            </p>
            <p style="margin:4px 0 12px 0;">
                <strong>Recommended fix:</strong> ${esc(f.recommendation)}
            </p>
            ${f.owasp ? `<p style="margin:4px 0;color:#8fa5bd;font-size:12px;">🔗 OWASP: ${esc(f.owasp)}</p>` : ''}
            <details>
                <summary style="cursor:pointer;color:#36d399;">View detected code</summary>
                <pre style="background:#06101b;padding:12px;border-radius:9px;overflow-x:auto;color:#b9d4eb;">${esc(f.snippet)}</pre>
            </details>
        </article>
    `).join("");
}

// ============================================================
// FORM SUBMISSION HANDLER
// ============================================================

form.addEventListener("submit", async (event) => {
    event.preventDefault();

    if (!input.files || !input.files.length) {
        statusBox.textContent = "⚠️ Please select a file first.";
        return;
    }

    const file = input.files[0];
    statusBox.textContent = `🔍 Scanning ${file.name}...`;
    results.classList.add("hidden");

    const data = new FormData();
    data.append("file", file);

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            body: data
        });

        const payload = await response.json();

        if (!response.ok) {
            throw new Error(payload.error || "Scan failed.");
        }

        // Update statistics
        document.getElementById("score").textContent = payload.score;
        document.getElementById("critical").textContent = payload.summary.critical;
        document.getElementById("high").textContent = payload.summary.high;
        document.getElementById("medium").textContent = payload.summary.medium;
        document.getElementById("low").textContent = payload.summary.low;
        document.getElementById("scanId").textContent = `Scan #${payload.scan_id} · ${payload.filename}`;

        // Render findings
        renderFindings(payload.findings);
        results.classList.remove("hidden");
        statusBox.textContent = `✅ Scan completed: ${payload.filename} (Score: ${payload.score}/100)`;
        
        // Scroll to results
        results.scrollIntoView({ behavior: 'smooth', block: 'start' });

    } catch (error) {
        statusBox.textContent = `❌ Error: ${error.message}`;
        console.error("Scan error:", error);
    }
});

// ============================================================
// KEYBOARD SHORTCUTS
// ============================================================

document.addEventListener("keydown", (event) => {
    // Press Ctrl+Enter to submit
    if (event.ctrlKey && event.key === "Enter") {
        form.dispatchEvent(new Event("submit"));
    }
});

// ============================================================
// LOADING ANIMATION
// ============================================================

// Add loading state to button
form.addEventListener("submit", () => {
    const button = form.querySelector("button");
    button.textContent = "⏳ Scanning...";
    button.disabled = true;
    
    // Reset after scan completes (handled in response)
    setTimeout(() => {
        button.textContent = "🔍 Scan Project";
        button.disabled = false;
    }, 3000);
});

// ============================================================
// DRAG AND DROP SUPPORT
// ============================================================

const dropZone = document.querySelector(".scanner-card");
if (dropZone) {
    dropZone.addEventListener("dragover", (event) => {
        event.preventDefault();
        dropZone.style.borderColor = "#36d399";
        dropZone.style.borderStyle = "solid";
    });

    dropZone.addEventListener("dragleave", () => {
        dropZone.style.borderColor = "#20384f";
        dropZone.style.borderStyle = "dashed";
    });

    dropZone.addEventListener("drop", (event) => {
        event.preventDefault();
        dropZone.style.borderColor = "#20384f";
        dropZone.style.borderStyle = "dashed";
        
        const files = event.dataTransfer.files;
        if (files.length > 0) {
            const file = files[0];
            if (file.name.endsWith(".py")) {
                input.files = files;
                statusBox.textContent = `📎 Selected: ${file.name}`;
            } else {
                statusBox.textContent = "⚠️ Please drop a .py file only.";
            }
        }
    });
}

console.log("🛡️ CodeGuard loaded successfully!");
console.log("📖 API Docs: http://127.0.0.1:8000/docs");