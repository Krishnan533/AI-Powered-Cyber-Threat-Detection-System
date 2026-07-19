// Telemetry Poller & Visualizations for SHIELD_IDS SOC Console

document.addEventListener("DOMContentLoaded", () => {
    let maxThreatId = 0;

    // Locked Color Palette for Plotly Charts
    const chartLayoutDefaults = {
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        font: {
            family: 'Inter, sans-serif',
            color: '#7C93AD',
            size: 11
        },
        xaxis: {
            gridcolor: 'rgba(0, 229, 255, 0.08)',
            linecolor: 'rgba(0, 229, 255, 0.15)',
            zeroline: false,
            tickfont: { color: '#7C93AD' }
        },
        yaxis: {
            gridcolor: 'rgba(0, 229, 255, 0.08)',
            linecolor: 'rgba(0, 229, 255, 0.15)',
            zeroline: false,
            tickfont: { color: '#7C93AD' }
        },
        margin: { t: 25, r: 15, b: 40, l: 40 }
    };

    // 1. Fetch & Render Dashboard Stats
    async function updateDashboardData() {
        try {
            // Fetch Stats
            const statsResp = await fetch('/api/dashboard/stats');
            if (statsResp.ok) {
                const stats = await statsResp.json();
                
                const totalPackets = stats.packets.total || 0;
                const activeThreats = stats.threats.active || 0;
                const resolvedThreats = stats.threats.resolved || 0;
                const blockedIps = stats.blocked_ips.active_count || 0;
                const aiAnomalies = stats.threats.ai_anomalies || 0;
                const packetsHour = stats.packets.last_hour || 0;

                document.getElementById("statTotalPackets").textContent = totalPackets.toLocaleString();
                document.getElementById("statPacketsHour").textContent = packetsHour.toLocaleString();
                document.getElementById("statActiveThreats").textContent = activeThreats.toLocaleString();
                document.getElementById("statResolvedThreats").textContent = resolvedThreats.toLocaleString();
                document.getElementById("statBlockedIPs").textContent = blockedIps.toLocaleString();
                document.getElementById("statAiAnomalies").textContent = aiAnomalies.toLocaleString();

                // Update Status Bar Threat Level Pill
                updateThreatLevelStatus(activeThreats, stats.threats.severities);
                
                // Draw Charts
                drawProtocolChart(stats.packets.protocols || {});
                drawSeverityChart(stats.threats.severities || {});
            }

            // Top IPs
            const topIpsResp = await fetch('/api/dashboard/top-ips');
            if (topIpsResp.ok) {
                const topIps = await topIpsResp.json();
                renderTopIps(topIps);
            }

            // Timeline Data
            const timelineResp = await fetch('/api/dashboard/timeline');
            if (timelineResp.ok) {
                const timeline = await timelineResp.json();
                drawTimelineChart(timeline);
            }

            // Live Feeds
            const feedResp = await fetch('/api/dashboard/live-feed');
            if (feedResp.ok) {
                const feeds = await feedResp.json();
                renderPacketsTable(feeds.packets || []);
                renderThreatsTable(feeds.threats || []);
            }

        } catch (err) {
            console.error("Error updating dashboard statistics:", err);
        }
    }

    // Update Top Status Bar Threat Pill
    function updateThreatLevelStatus(activeThreats, severities) {
        const pill = document.getElementById("threatLevelPill");
        const text = document.getElementById("threatLevelText");
        if (!pill || !text) return;

        const criticalCount = severities?.Critical || 0;
        const highCount = severities?.High || 0;

        if (criticalCount > 0) {
            pill.className = "threat-level-pill critical";
            text.textContent = "CRITICAL THREAT LEVEL";
        } else if (activeThreats > 3 || highCount > 0) {
            pill.className = "threat-level-pill elevated";
            text.textContent = "ELEVATED THREAT LEVEL";
        } else {
            pill.className = "threat-level-pill normal";
            text.textContent = "NORMAL THREAT LEVEL";
        }
    }

    // 2. Chart Rendering Functions
    function drawProtocolChart(protocols) {
        const container = document.getElementById("chartProtocol");
        if (!container) return;

        const labels = Object.keys(protocols || {});
        const values = Object.values(protocols || {});

        if (labels.length === 0 || values.reduce((a, b) => a + b, 0) === 0) {
            container.innerHTML = `<div class="d-flex flex-column align-items-center justify-content-center h-100 text-grey font-mono text-center p-3">
                <i class="fa-solid fa-chart-pie fa-2xl mb-2 text-muted"></i>
                <div style="font-size: 0.85rem;">No protocol telemetry for this window</div>
                <button class="btn btn-outline-cyan btn-sm mt-2 font-mono" style="font-size: 0.75rem;" onclick="updateDashboardData()">Retry Fetch</button>
            </div>`;
            return;
        }

        // State: LOADED — Clear loading overlay text before Plotly render
        container.innerHTML = "";

        const data = [{
            values: values,
            labels: labels,
            type: 'pie',
            hole: 0.55,
            marker: {
                colors: ['#00E5FF', '#2F6FFF', '#00E676', '#FFB020', '#7C93AD']
            },
            textinfo: 'percent',
            hoverinfo: 'label+value+percent'
        }];

        const layout = {
            ...chartLayoutDefaults,
            margin: { t: 10, r: 10, b: 10, l: 10 },
            showlegend: true,
            legend: {
                orientation: 'h',
                x: 0,
                y: -0.15,
                font: { color: '#E7F3FF', size: 10 }
            }
        };

        Plotly.newPlot(container, data, layout, { responsive: true, displayModeBar: false });
    }

    function drawSeverityChart(severities) {
        const container = document.getElementById("chartSeverity");
        if (!container) return;

        const categories = ['Low', 'Medium', 'High', 'Critical'];
        const values = categories.map(cat => (severities && severities[cat]) || 0);

        if (values.reduce((a, b) => a + b, 0) === 0) {
            container.innerHTML = `<div class="d-flex flex-column align-items-center justify-content-center h-100 text-grey font-mono text-center p-3">
                <i class="fa-solid fa-chart-simple fa-2xl mb-2 text-muted"></i>
                <div style="font-size: 0.85rem;">No threat severity alerts in window</div>
            </div>`;
            return;
        }

        // State: LOADED — Clear loading overlay text before Plotly render
        container.innerHTML = "";

        const data = [{
            x: categories,
            y: values,
            type: 'bar',
            marker: {
                color: ['#7C93AD', '#00E5FF', '#FFB020', '#FF3B5C'],
                line: { width: 0 }
            }
        }];

        const layout = {
            ...chartLayoutDefaults,
            margin: { t: 20, r: 15, b: 40, l: 40 },
            xaxis: {
                ...chartLayoutDefaults.xaxis,
                type: 'category'
            }
        };

        Plotly.newPlot(container, data, layout, { responsive: true, displayModeBar: false });
    }

    function drawTimelineChart(timeline) {
        const container = document.getElementById("chartTimeline");
        if (!container) return;

        if (!timeline || timeline.length === 0) {
            container.innerHTML = `<div class="d-flex flex-column align-items-center justify-content-center h-100 text-grey font-mono text-center p-3">
                <i class="fa-solid fa-chart-line fa-2xl mb-2 text-muted"></i>
                <div style="font-size: 0.85rem;">No telemetry data for this window</div>
                <button class="btn btn-outline-cyan btn-sm mt-2 font-mono" style="font-size: 0.75rem;" onclick="updateDashboardData()">Retry Fetch</button>
            </div>`;
            return;
        }

        // Check if dataset has 0 packet volume
        const totalPackets = timeline.reduce((acc, row) => acc + (row.packets || 0), 0);
        if (totalPackets === 0) {
            console.warn("[Telemetry Warning] Timeline dataset fetched has 0 packet volume.");
        }

        // State: LOADED — Clear loading overlay text before Plotly render
        container.innerHTML = "";

        const timestamps = timeline.map(row => row.timestamp.split(' ')[1] || row.timestamp);
        const packets = timeline.map(row => row.packets);
        const threats = timeline.map(row => row.threats);

        const tracePackets = {
            x: timestamps,
            y: packets,
            name: 'Packet Volume',
            type: 'scatter',
            mode: 'lines',
            line: { color: '#00E5FF', width: 2, shape: 'spline' }
        };

        const traceThreats = {
            x: timestamps,
            y: threats,
            name: 'Security Alerts',
            type: 'scatter',
            mode: 'lines+markers',
            yaxis: 'y2',
            line: { color: '#FF3B5C', width: 1.5, shape: 'spline' },
            marker: { size: 5, color: '#FF3B5C' }
        };

        const data = [tracePackets, traceThreats];

        const layout = {
            ...chartLayoutDefaults,
            showlegend: true,
            legend: {
                orientation: 'h',
                x: 0,
                y: 1.12,
                font: { color: '#E7F3FF', size: 10 }
            },
            yaxis: {
                title: 'Packets / sec',
                titlefont: { color: '#00E5FF', size: 10 },
                tickfont: { color: '#00E5FF' },
                gridcolor: 'rgba(0, 229, 255, 0.08)',
                linecolor: 'rgba(0, 229, 255, 0.15)',
                zeroline: false,
                rangemode: 'tozero',
                autorange: true
            },
            yaxis2: {
                title: 'Threat Alerts',
                titlefont: { color: '#FF3B5C', size: 10 },
                tickfont: { color: '#FF3B5C' },
                overlaying: 'y',
                side: 'right',
                gridcolor: 'rgba(0,0,0,0)',
                linecolor: 'rgba(255, 59, 92, 0.2)',
                zeroline: false,
                rangemode: 'tozero',
                autorange: true
            }
        };

        Plotly.newPlot(container, data, layout, { responsive: true, displayModeBar: false });
    }

    // 3. Render Table Data Feeds
    function renderPacketsTable(packets) {
        const body = document.querySelector("#livePacketTable tbody");
        if (!packets || packets.length === 0) {
            body.innerHTML = `<tr><td colspan="5" class="text-center py-4 text-grey">Awaiting packet stream...</td></tr>`;
            return;
        }

        body.innerHTML = "";
        packets.forEach(p => {
            const time = p.timestamp ? p.timestamp.split('T')[1].substring(0, 8) : "";
            
            let protoClass = "text-white";
            if (p.protocol === "TCP") protoClass = "text-neon-cyan";
            else if (p.protocol === "UDP") protoClass = "text-neon-blue";
            else if (p.protocol === "ICMP") protoClass = "text-neon-green";

            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td class="text-grey">${time}</td>
                <td class="text-white font-weight-bold">${p.src_ip}</td>
                <td class="text-grey">${p.dst_ip}</td>
                <td><span class="${protoClass}">${p.protocol}</span></td>
                <td class="text-end text-grey tabular-nums">${p.packet_size.toLocaleString()} B</td>
            `;
            body.appendChild(tr);
        });
    }

    function renderThreatsTable(threats) {
        const body = document.querySelector("#criticalThreatTable tbody");
        if (!threats || threats.length === 0) {
            body.innerHTML = `<tr><td colspan="5" class="text-center py-4 text-grey">No active threat alerts in logs.</td></tr>`;
            return;
        }

        // Pulse Mini Globe on new alert arrival
        threats.forEach(t => {
            if (maxThreatId > 0 && t.id > maxThreatId && t.status === 'Active') {
                const isCritical = t.severity_level === 'Critical';
                if (window.ThreatGlobe) {
                    window.ThreatGlobe.triggerMiniGlobePulse(isCritical);
                }
                showToast(`[ALERT] ${t.severity_level} threat: ${t.type} from ${t.source_ip}`, isCritical ? "danger" : "warning");
            }
        });

        if (threats.length > 0) {
            const ids = threats.map(t => t.id);
            maxThreatId = Math.max(maxThreatId, ...ids);
        }

        body.innerHTML = "";
        threats.forEach(t => {
            const time = t.timestamp ? t.timestamp.split('T')[1].substring(0, 8) : "";
            
            let badgeClass = "bg-neon-cyan-outline";
            if (t.severity_level === "Critical") badgeClass = "bg-neon-red-outline";
            else if (t.severity_level === "High") badgeClass = "bg-neon-amber-outline";
            else if (t.severity_level === "Medium") badgeClass = "bg-neon-cyan-outline";

            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td class="text-white font-weight-bold"><i class="fa-solid fa-triangle-exclamation text-neon-red me-1"></i> ${t.type}</td>
                <td class="text-neon-cyan font-weight-bold">${t.source_ip}</td>
                <td><span class="badge ${badgeClass}">${t.severity_level}</span></td>
                <td class="text-grey">${time}</td>
                <td class="text-end">
                    <a href="/threats?search=${t.source_ip}" class="btn btn-outline-cyan btn-sm font-mono" style="font-size: 0.65rem;">Inspect</a>
                </td>
            `;
            body.appendChild(tr);
        });
    }

    function renderTopIps(data) {
        const sourceBody = document.querySelector('#topSourcesBody');
        const destBody = document.querySelector('#topDestinationsBody');

        if (!data || (!data.sources?.length && !data.destinations?.length)) {
            sourceBody.innerHTML = `<tr><td colspan="2" class="text-center py-2 text-grey">No source IPs yet</td></tr>`;
            destBody.innerHTML = `<tr><td colspan="2" class="text-center py-2 text-grey">No destination IPs yet</td></tr>`;
            return;
        }

        if (data.sources?.length) {
            sourceBody.innerHTML = '';
            data.sources.slice(0, 4).forEach(source => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="text-white font-mono">${source.ip}</td>
                    <td class="text-end text-grey tabular-nums">${source.count.toLocaleString()}</td>
                `;
                sourceBody.appendChild(tr);
            });
        }

        if (data.destinations?.length) {
            destBody.innerHTML = '';
            data.destinations.slice(0, 4).forEach(dest => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="text-white font-mono">${dest.ip}</td>
                    <td class="text-end text-grey tabular-nums">${dest.count.toLocaleString()}</td>
                `;
                destBody.appendChild(tr);
            });
        }
    }

    // 4. Retrain Trigger
    const retrainBtn = document.getElementById("retrainBtn");
    if (retrainBtn) {
        retrainBtn.addEventListener("click", async () => {
            const token = document.getElementById("globalCsrfToken").value;
            retrainBtn.disabled = true;
            retrainBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> <span>RETRAINING ENGINE...</span>`;

            try {
                const response = await fetch('/api/dashboard/retrain', {
                    method: 'POST',
                    headers: {
                        'Accept': 'application/json',
                        'X-CSRF-Token': token
                    }
                });

                const data = await response.json();
                if (response.ok && data.success) {
                    showToast("AI Isolation Forest retrain job dispatched.", "success");
                } else {
                    showToast(data.message || "Failed to trigger retraining.", "danger");
                }
            } catch (err) {
                console.error(err);
                showToast("Server communication error.", "danger");
            } finally {
                retrainBtn.disabled = false;
                retrainBtn.innerHTML = `<i class="fa-solid fa-rotate"></i> <span>RETRAIN ANOMALY ENGINE</span>`;
            }
        });
    }

    // Initial load and polling
    updateDashboardData();
    setInterval(updateDashboardData, 3000);
});
