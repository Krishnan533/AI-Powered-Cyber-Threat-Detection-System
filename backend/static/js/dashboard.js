// Dashboard Telemetry Poller and Chart Drawer

document.addEventListener("DOMContentLoaded", () => {
    // 1. Plotly styling configurations matching our theme
    const chartLayoutDefaults = {
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        font: {
            family: 'Outfit, sans-serif',
            color: '#cbd5e1',
            size: 11
        },
        xaxis: {
            gridcolor: '#1e293b',
            linecolor: '#1e293b',
            zeroline: false
        },
        yaxis: {
            gridcolor: '#1e293b',
            linecolor: '#1e293b',
            zeroline: false
        },
        margin: { t: 25, r: 15, b: 40, l: 40 }
    };

    // 2. Fetch and render all statistics
    async function updateDashboardData() {
        try {
            // Stats counts
            const statsResp = await fetch('/api/dashboard/stats');
            if (statsResp.ok) {
                const stats = await statsResp.json();
                
                document.getElementById("statTotalPackets").textContent = stats.packets.total.toLocaleString();
                document.getElementById("statPacketsHour").textContent = stats.packets.last_hour.toLocaleString();
                document.getElementById("statActiveThreats").textContent = stats.threats.active.toLocaleString();
                document.getElementById("statResolvedThreats").textContent = stats.threats.resolved.toLocaleString();
                document.getElementById("statBlockedIPs").textContent = stats.blocked_ips.active_count.toLocaleString();
                document.getElementById("statAiAnomalies").textContent = stats.threats.ai_anomalies.toLocaleString();
                
                // Draw charts
                drawProtocolChart(stats.packets.protocols);
                drawSeverityChart(stats.threats.severities);
            }

            // Top source/destination IP analytics
            const topIpsResp = await fetch('/api/dashboard/top-ips');
            if (topIpsResp.ok) {
                const topIps = await topIpsResp.json();
                renderTopIps(topIps);
            }

            // Timeline charts
            const timelineResp = await fetch('/api/dashboard/timeline');
            if (timelineResp.ok) {
                const timeline = await timelineResp.json();
                drawTimelineChart(timeline);
            }

            // Feeds lists
            const feedResp = await fetch('/api/dashboard/live-feed');
            if (feedResp.ok) {
                const feeds = await feedResp.json();
                renderPacketsTable(feeds.packets);
                renderThreatsTable(feeds.threats);
            }

        } catch (err) {
            console.error("Error fetching dashboard statistics:", err);
        }
    }

    // 3. Render charts utilizing Plotly
    function drawProtocolChart(protocols) {
        const labels = Object.keys(protocols);
        const values = Object.values(protocols);

        if (labels.length === 0) {
            document.getElementById("chartProtocol").innerHTML = `<div class="d-flex align-items-center justify-content-center h-100 text-grey">No protocols recorded yet.</div>`;
            return;
        }

        const data = [{
            values: values,
            labels: labels,
            type: 'pie',
            hole: 0.5,
            marker: {
                colors: ['#00f2fe', '#b557f6', '#00ff66', '#ffb300', '#64748b']
            },
            textinfo: 'percent',
            hoverinfo: 'label+value+percent'
        }];

        const layout = {
            ...chartLayoutDefaults,
            margin: { t: 15, r: 15, b: 15, l: 15 },
            showlegend: true,
            legend: {
                orientation: 'h',
                x: 0,
                y: -0.1,
                font: { size: 10 }
            }
        };

        Plotly.newPlot('chartProtocol', data, layout, { responsive: true, displayModeBar: false });
    }

    function drawSeverityChart(severities) {
        const categories = ['Low', 'Medium', 'High', 'Critical'];
        const values = categories.map(cat => severities[cat] || 0);

        const data = [{
            x: categories,
            y: values,
            type: 'bar',
            marker: {
                color: ['#64748b', '#00f2fe', '#ffb300', '#ff3838'],
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

        Plotly.newPlot('chartSeverity', data, layout, { responsive: true, displayModeBar: false });
    }

    function drawTimelineChart(timeline) {
        if (timeline.length === 0) {
            document.getElementById("chartTimeline").innerHTML = `<div class="d-flex align-items-center justify-content-center h-100 text-grey">No timeline data available.</div>`;
            return;
        }

        const timestamps = timeline.map(row => row.timestamp.split(' ')[1]); // extraction only time string hh:mm
        const packets = timeline.map(row => row.packets);
        const threats = timeline.map(row => row.threats);

        const tracePackets = {
            x: timestamps,
            y: packets,
            name: 'Total Traffic',
            type: 'scatter',
            mode: 'lines',
            line: { color: '#00f2fe', width: 2, shape: 'spline' }
        };

        const traceThreats = {
            x: timestamps,
            y: threats,
            name: 'Threat Alerts',
            type: 'scatter',
            mode: 'lines+markers',
            yaxis: 'y2',
            line: { color: '#ff3838', width: 1.5, shape: 'spline' },
            marker: { size: 4, color: '#ff3838' }
        };

        const data = [tracePackets, traceThreats];

        const layout = {
            ...chartLayoutDefaults,
            showlegend: true,
            legend: {
                orientation: 'h',
                x: 0,
                y: 1.1,
                font: { size: 10 }
            },
            yaxis: {
                title: 'Packet Volume',
                titlefont: { color: '#00f2fe', size: 10 },
                tickfont: { color: '#00f2fe' },
                gridcolor: '#1e293b',
                linecolor: '#1e293b',
                zeroline: false
            },
            yaxis2: {
                title: 'Threat Alerts',
                titlefont: { color: '#ff3838', size: 10 },
                tickfont: { color: '#ff3838' },
                overlaying: 'y',
                side: 'right',
                gridcolor: 'rgba(0,0,0,0)', // hide right grid lines
                linecolor: '#1e293b',
                zeroline: false
            }
        };

        Plotly.newPlot('chartTimeline', data, layout, { responsive: true, displayModeBar: false });
    }

    // 4. Render feed grids
    function renderPacketsTable(packets) {
        const body = document.querySelector("#livePacketTable tbody");
        if (packets.length === 0) {
            body.innerHTML = `<tr><td colspan="5" class="text-center py-4 text-grey">Awaiting packet stream...</td></tr>`;
            return;
        }

        body.innerHTML = "";
        packets.forEach(p => {
            const time = p.timestamp ? p.timestamp.split('T')[1].substring(0, 8) : "";
            
            let protoClass = "text-white";
            if (p.protocol === "TCP") protoClass = "text-neon-cyan";
            else if (p.protocol === "UDP") protoClass = "text-neon-purple";
            else if (p.protocol === "ICMP") protoClass = "text-neon-green";

            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td class="text-grey">${time}</td>
                <td class="text-white font-weight-bold">${p.src_ip}</td>
                <td>${p.dst_ip}</td>
                <td><span class="${protoClass}">${p.protocol}</span></td>
                <td class="text-end text-grey">${p.packet_size.toLocaleString()}</td>
            `;
            body.appendChild(tr);
        });
    }

    function renderThreatsTable(threats) {
        const body = document.querySelector("#criticalThreatTable tbody");
        if (threats.length === 0) {
            body.innerHTML = `<tr><td colspan="5" class="text-center py-4 text-grey">No active threat alerts logged.</td></tr>`;
            return;
        }

        body.innerHTML = "";
        threats.forEach(t => {
            const time = t.timestamp ? t.timestamp.split('T')[1].substring(0, 8) : "";
            
            let badgeClass = "bg-secondary";
            if (t.severity_level === "Critical") badgeClass = "bg-neon-red text-dark";
            else if (t.severity_level === "High") badgeClass = "bg-neon-amber text-dark";
            else if (t.severity_level === "Medium") badgeClass = "bg-neon-cyan text-dark";

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
            sourceBody.innerHTML = `<tr><td colspan="2" class="text-center py-3 text-grey" style="font-size: 0.8rem;">No source IPs yet.</td></tr>`;
            destBody.innerHTML = `<tr><td colspan="2" class="text-center py-3 text-grey" style="font-size: 0.8rem;">No destination IPs yet.</td></tr>`;
            return;
        }

        if (data.sources?.length) {
            sourceBody.innerHTML = '';
            data.sources.slice(0, 5).forEach(source => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="text-white font-mono">${source.ip}</td>
                    <td class="text-end text-grey">${source.count.toLocaleString()}</td>
                `;
                sourceBody.appendChild(tr);
            });
        } else {
            sourceBody.innerHTML = `<tr><td colspan="2" class="text-center py-3 text-grey" style="font-size: 0.8rem;">No source IPs yet.</td></tr>`;
        }

        if (data.destinations?.length) {
            destBody.innerHTML = '';
            data.destinations.slice(0, 5).forEach(dest => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="text-white font-mono">${dest.ip}</td>
                    <td class="text-end text-grey">${dest.count.toLocaleString()}</td>
                `;
                destBody.appendChild(tr);
            });
        } else {
            destBody.innerHTML = `<tr><td colspan="2" class="text-center py-3 text-grey" style="font-size: 0.8rem;">No destination IPs yet.</td></tr>`;
        }
    }

    // 5. Bind retrain trigger
    const retrainBtn = document.getElementById("retrainBtn");
    if (retrainBtn) {
        retrainBtn.addEventListener("click", async () => {
            const token = document.getElementById("globalCsrfToken").value;
            retrainBtn.disabled = true;
            retrainBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> <span>RETRAINING...</span>`;

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
                    showToast("AI Anomaly Model retrain job scheduled successfully.", "success");
                } else {
                    showToast(data.message || "Failed to trigger model retraining.", "danger");
                }
            } catch (err) {
                console.error(err);
                showToast("Failed to connect to server.", "danger");
            } finally {
                retrainBtn.disabled = false;
                retrainBtn.innerHTML = `<i class="fa-solid fa-rotate"></i> <span>RETRAIN ANOMALY ENGINE</span>`;
            }
        });
    }

    // 6. Polling loop triggers (run every 3 seconds to keep stats alive)
    updateDashboardData();
    setInterval(updateDashboardData, 3000);
});
