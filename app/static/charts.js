// ============================================================
// CHARTS.JS - Dashboard Charts
// ============================================================

let scoreChartInstance = null;
let severityChartInstance = null;

function initializeCharts() {
    const scoreCtx = document.getElementById('scoreChart');
    if (scoreCtx) {
        scoreChartInstance = new Chart(scoreCtx, {
            type: 'line',
            data: {
                labels: ['Scan 1', 'Scan 2', 'Scan 3', 'Scan 4', 'Scan 5'],
                datasets: [{
                    label: 'Security Score',
                    data: [85, 70, 92, 45, 78],
                    borderColor: '#36d399',
                    backgroundColor: 'rgba(54, 211, 153, 0.1)',
                    borderWidth: 3,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { labels: { color: '#8fa5bd' } }
                },
                scales: {
                    y: { beginAtZero: true, max: 100, ticks: { color: '#8fa5bd' } },
                    x: { ticks: { color: '#8fa5bd' } }
                }
            }
        });
    }

    const severityCtx = document.getElementById('severityChart');
    if (severityCtx) {
        severityChartInstance = new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#ff5d73', '#ff8b62', '#ffb454', '#54a8ff'],
                    borderWidth: 2,
                    borderColor: '#1a2236'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'bottom', labels: { color: '#8fa5bd' } }
                }
            }
        });
    }
}

function updateCharts(score, summary) {
    if (scoreChartInstance) {
        const currentData = scoreChartInstance.data.datasets[0].data;
        currentData.push(score);
        if (currentData.length > 10) { currentData.shift(); }
        scoreChartInstance.update();
    }
    if (severityChartInstance) {
        severityChartInstance.data.datasets[0].data = [
            summary.critical || 0,
            summary.high || 0,
            summary.medium || 0,
            summary.low || 0
        ];
        severityChartInstance.update();
    }
}

document.addEventListener('DOMContentLoaded', initializeCharts);