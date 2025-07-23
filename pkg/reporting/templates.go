/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: templates.go
Description: HTML templates for the Akaylee Fuzzer dashboard. Provides beautiful,
modern, and responsive web interface with interactive charts and comprehensive
fuzzing metrics visualization.
*/

package reporting

// dashboardTemplate is the main HTML template for the dashboard
const dashboardTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}} - Akaylee Fuzzer Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns/dist/chartjs-adapter-date-fns.bundle.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            text-align: center;
        }

        .header h1 {
            color: #4a5568;
            font-size: 2.5rem;
            margin-bottom: 10px;
            font-weight: 700;
        }

        .header p {
            color: #718096;
            font-size: 1.1rem;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.15);
        }

        .stat-card h3 {
            color: #4a5568;
            font-size: 1.2rem;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .stat-card .value {
            font-size: 2.5rem;
            font-weight: 700;
            color: #2d3748;
            margin-bottom: 5px;
        }

        .stat-card .label {
            color: #718096;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 30px;
            margin-bottom: 30px;
        }

        .chart-container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }

        .chart-container h3 {
            color: #4a5568;
            font-size: 1.3rem;
            margin-bottom: 20px;
            text-align: center;
        }

        .chart-wrapper {
            position: relative;
            height: 300px;
        }

        .tabs {
            display: flex;
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 5px;
            margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }

        .tab {
            flex: 1;
            padding: 15px 20px;
            text-align: center;
            cursor: pointer;
            border-radius: 10px;
            transition: all 0.3s ease;
            color: #718096;
            font-weight: 500;
        }

        .tab.active {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }

        .tab:hover:not(.active) {
            background: rgba(102, 126, 234, 0.1);
            color: #667eea;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .crash-list {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }

        .crash-item {
            background: #f7fafc;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #e53e3e;
            transition: all 0.3s ease;
        }

        .crash-item:hover {
            transform: translateX(5px);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }

        .crash-item.critical { border-left-color: #e53e3e; }
        .crash-item.high { border-left-color: #dd6b20; }
        .crash-item.medium { border-left-color: #d69e2e; }
        .crash-item.low { border-left-color: #38a169; }

        .crash-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }

        .crash-title {
            font-weight: 600;
            color: #2d3748;
        }

        .crash-severity {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .crash-severity.critical { background: #fed7d7; color: #c53030; }
        .crash-severity.high { background: #feebc8; color: #dd6b20; }
        .crash-severity.medium { background: #fef5e7; color: #d69e2e; }
        .crash-severity.low { background: #c6f6d5; color: #38a169; }

        .crash-details {
            color: #718096;
            font-size: 0.9rem;
        }

        .footer {
            text-align: center;
            padding: 30px;
            color: rgba(255, 255, 255, 0.8);
            font-size: 0.9rem;
        }

        .icon {
            width: 20px;
            height: 20px;
        }

        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .charts-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            }
        }

        .loading {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 200px;
            color: #718096;
        }

        .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            margin-right: 10px;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-bug"></i> {{.Title}}</h1>
            <p>Generated on {{.GeneratedAt.Format "January 2, 2006 at 3:04 PM"}} | Session: {{.SessionID}} | Version: {{.Version}}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <h3><i class="fas fa-play-circle"></i> Executions</h3>
                <div class="value">{{.FuzzerStats.Executions}}</div>
                <div class="label">Total Test Cases</div>
            </div>
            <div class="stat-card">
                <h3><i class="fas fa-tachometer-alt"></i> Rate</h3>
                <div class="value">{{printf "%.1f" .FuzzerStats.ExecutionsPerSecond}}</div>
                <div class="label">Executions/Second</div>
            </div>
            <div class="stat-card">
                <h3><i class="fas fa-exclamation-triangle"></i> Crashes</h3>
                <div class="value">{{.FuzzerStats.Crashes}}</div>
                <div class="label">Total Crashes</div>
            </div>
            <div class="stat-card">
                <h3><i class="fas fa-clock"></i> Hangs</h3>
                <div class="value">{{.FuzzerStats.Hangs}}</div>
                <div class="label">Total Hangs</div>
            </div>
            <div class="stat-card">
                <h3><i class="fas fa-chart-line"></i> Coverage</h3>
                <div class="value">{{.CoverageStats.CoveragePercentage | printf "%.1f"}}%</div>
                <div class="label">Coverage Percentage</div>
            </div>
            <div class="stat-card">
                <h3><i class="fas fa-layer-group"></i> States</h3>
                <div class="value">{{.StateStats.UniqueStates}}</div>
                <div class="label">Unique States</div>
            </div>
        </div>

        <div class="tabs">
            <div class="tab active" onclick="showTab('overview')">
                <i class="fas fa-chart-bar"></i> Overview
            </div>
            <div class="tab" onclick="showTab('crashes')">
                <i class="fas fa-exclamation-triangle"></i> Crashes
            </div>
            <div class="tab" onclick="showTab('coverage')">
                <i class="fas fa-chart-line"></i> Coverage
            </div>
            <div class="tab" onclick="showTab('states')">
                <i class="fas fa-layer-group"></i> States
            </div>
            <div class="tab" onclick="showTab('performance')">
                <i class="fas fa-tachometer-alt"></i> Performance
            </div>
        </div>

        <div id="overview" class="tab-content active">
            <div class="charts-grid">
                <div class="chart-container">
                    <h3>Execution Rate Over Time</h3>
                    <div class="chart-wrapper">
                        <canvas id="executionRateChart"></canvas>
                    </div>
                </div>
                <div class="chart-container">
                    <h3>Coverage Distribution</h3>
                    <div class="chart-wrapper">
                        <canvas id="coverageChart"></canvas>
                    </div>
                </div>
                <div class="chart-container">
                    <h3>Crash Distribution by Severity</h3>
                    <div class="chart-wrapper">
                        <canvas id="crashChart"></canvas>
                    </div>
                </div>
                <div class="chart-container">
                    <h3>State Exploration Over Time</h3>
                    <div class="chart-wrapper">
                        <canvas id="stateChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <div id="crashes" class="tab-content">
            <div class="crash-list">
                <h3><i class="fas fa-exclamation-triangle"></i> Recent Crashes</h3>
                {{range .CrashReports}}
                <div class="crash-item {{.Severity}}">
                    <div class="crash-header">
                        <div class="crash-title">{{.Type}}</div>
                        <div class="crash-severity {{.Severity}}">{{.Severity}}</div>
                    </div>
                    <div class="crash-details">
                        <p><strong>Time:</strong> {{.Timestamp.Format "2006-01-02 15:04:05"}}</p>
                        <p><strong>Signal:</strong> {{.Signal}} | <strong>Exit Code:</strong> {{.ExitCode}}</p>
                        <p><strong>Reproducible:</strong> {{if .Reproducible}}Yes{{else}}No{{end}} | <strong>Exploitable:</strong> {{if .Exploitable}}Yes{{else}}No{{end}}</p>
                        <p><strong>Input Size:</strong> {{.InputSize}} bytes | <strong>Hash:</strong> {{.Hash}}</p>
                    </div>
                </div>
                {{end}}
            </div>
        </div>

        <div id="coverage" class="tab-content">
            <div class="loading">
                <div class="spinner"></div>
                <span>Coverage details loading...</span>
            </div>
        </div>

        <div id="states" class="tab-content">
            <div class="loading">
                <div class="spinner"></div>
                <span>State details loading...</span>
            </div>
        </div>

        <div id="performance" class="tab-content">
            <div class="loading">
                <div class="spinner"></div>
                <span>Performance details loading...</span>
            </div>
        </div>
    </div>

    <div class="footer">
        <p>&copy; 2024 Akaylee Fuzzer - Enterprise-Grade Fuzzing Engine</p>
    </div>

    <script>
        // Chart.js configuration
        Chart.defaults.font.family = "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif";
        Chart.defaults.color = '#4a5568';

        // Initialize charts
        const executionRateChart = new Chart(
            document.getElementById('executionRateChart'),
            {{.Charts.ExecutionRateChart | json}}
        );

        const coverageChart = new Chart(
            document.getElementById('coverageChart'),
            {{.Charts.CoverageChart | json}}
        );

        const crashChart = new Chart(
            document.getElementById('crashChart'),
            {{.Charts.CrashChart | json}}
        );

        const stateChart = new Chart(
            document.getElementById('stateChart'),
            {{.Charts.StateChart | json}}
        );

        // Tab functionality
        function showTab(tabName) {
            // Hide all tab contents
            const tabContents = document.querySelectorAll('.tab-content');
            tabContents.forEach(content => content.classList.remove('active'));

            // Remove active class from all tabs
            const tabs = document.querySelectorAll('.tab');
            tabs.forEach(tab => tab.classList.remove('active'));

            // Show selected tab content
            document.getElementById(tabName).classList.add('active');

            // Add active class to clicked tab
            event.target.classList.add('active');
        }

        // Auto-refresh functionality (optional)
        function refreshData() {
            // Implementation for real-time data updates
            console.log('Refreshing dashboard data...');
        }

        // Refresh every 30 seconds if needed
        // setInterval(refreshData, 30000);
    </script>
</body>
</html>`
