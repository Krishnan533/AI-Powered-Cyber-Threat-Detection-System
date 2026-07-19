// Global Javascript Functions for SHIELD_IDS Dashboard

document.addEventListener("DOMContentLoaded", () => {
    // 1. Clock Updates (Responsive: condensed time on narrow screens, full timestamp on tap)
    const realtimeClock = document.getElementById("realtimeClock");
    if (realtimeClock) {
        let showFullDate = false;
        
        realtimeClock.style.cursor = "pointer";
        realtimeClock.title = "Click to toggle full date/time";
        realtimeClock.addEventListener("click", () => {
            showFullDate = !showFullDate;
            updateClock();
        });

        const updateClock = () => {
            const now = new Date();
            const fullStr = now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
            const timeOnlyStr = now.toISOString().substring(11, 19) + ' UTC';
            
            if (window.innerWidth < 576 && !showFullDate) {
                realtimeClock.textContent = timeOnlyStr;
            } else {
                realtimeClock.textContent = fullStr;
            }
        };

        updateClock();
        setInterval(updateClock, 1000);
        window.addEventListener("resize", updateClock);
    }

    // 2. Bind Log Out Button
    const logoutBtn = document.getElementById("logoutBtn");
    if (logoutBtn) {
        logoutBtn.addEventListener("click", async () => {
            const tokenEl = document.getElementById("globalCsrfToken");
            const token = tokenEl ? tokenEl.value : "";
            try {
                const response = await fetch('/api/auth/logout', {
                    method: 'POST',
                    headers: {
                        'Accept': 'application/json',
                        'X-CSRF-Token': token
                    }
                });
                
                if (response.ok) {
                    window.location.href = '/login';
                } else {
                    console.error("Logout API request non-OK, redirecting to /logout.");
                    window.location.href = '/logout';
                }
            } catch (err) {
                console.error("Error communicating during logout:", err);
                window.location.href = '/logout';
            }
        });
    }
});

// 3. Dynamic Toast Notification System
/**
 * Triggers a slide-in alert toast in a dedicated top-right fixed container.
 * 
 * @param {string} message - Notification text content.
 * @param {string} category - Type: 'success', 'danger', 'warning', 'info'
 */
function showToast(message, category = "info") {
    let container = document.getElementById("toastContainer");
    if (!container) {
        container = document.createElement("div");
        container.id = "toastContainer";
        document.body.appendChild(container);
    }

    const toastEl = document.createElement("div");
    toastEl.className = "toast align-items-center text-white border-0 glass-panel show";
    toastEl.setAttribute("role", "alert");
    toastEl.setAttribute("aria-live", "assertive");
    toastEl.setAttribute("aria-atomic", "true");

    let borderClass = "border-start border-4 border-info";
    let iconClass = "fa-circle-info text-neon-cyan";

    if (category === "success") {
        borderClass = "border-start border-4 border-success";
        iconClass = "fa-circle-check text-neon-green";
    } else if (category === "danger" || category === "critical") {
        borderClass = "border-start border-4 border-danger";
        iconClass = "fa-circle-exclamation text-neon-red";
    } else if (category === "warning") {
        borderClass = "border-start border-4 border-warning";
        iconClass = "fa-triangle-exclamation text-neon-amber";
    }

    toastEl.classList.add(...borderClass.split(' '));

    toastEl.innerHTML = `
        <div class="d-flex align-items-start gap-3">
            <i class="fa-solid ${iconClass} fa-lg mt-1"></i>
            <div class="toast-body p-0 text-white font-mono" style="font-size: 0.82rem; line-height: 1.4; word-break: break-word; overflow-wrap: anywhere;">
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white" aria-label="Close"></button>
        </div>
    `;

    // Cap visible toasts at 3 max — remove oldest if container has 3 or more toasts
    while (container.children.length >= 3) {
        const oldest = container.firstChild;
        if (oldest && oldest.parentNode) {
            oldest.parentNode.removeChild(oldest);
        } else {
            break;
        }
    }

    container.appendChild(toastEl);

    let dismissed = false;
    const removeToast = () => {
        if (dismissed) return;
        dismissed = true;
        toastEl.classList.remove("show");
        toastEl.classList.add("fade");
        setTimeout(() => {
            if (toastEl && toastEl.parentNode) {
                toastEl.parentNode.removeChild(toastEl);
            }
        }, 200);
    };

    const closeBtn = toastEl.querySelector(".btn-close");
    if (closeBtn) {
        closeBtn.addEventListener("click", removeToast);
    }
    
    setTimeout(removeToast, 5500);
}

