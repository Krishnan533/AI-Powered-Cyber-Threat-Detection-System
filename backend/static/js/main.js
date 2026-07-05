// Global Javascript Functions for SHIELD_IDS Dashboard

document.addEventListener("DOMContentLoaded", () => {
    // 1. Clock Updates
    const realtimeClock = document.getElementById("realtimeClock");
    if (realtimeClock) {
        const updateClock = () => {
            const now = new Date();
            const utcTimeStr = now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
            realtimeClock.textContent = utcTimeStr;
        };
        updateClock();
        setInterval(updateClock, 1000);
    }

    // 2. Bind Log Out Button
    const logoutBtn = document.getElementById("logoutBtn");
    if (logoutBtn) {
        logoutBtn.addEventListener("click", async () => {
            const token = document.getElementById("globalCsrfToken").value;
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
                    console.error("Logout request rejected by server.");
                    window.location.reload();
                }
            } catch (err) {
                console.error("Error communicating during logout:", err);
                window.location.href = '/login'; // Fallback redirect anyway
            }
        });
    }
});

// 3. Dynamic Toast Notification System
/**
 * Triggers a slide-in alert warning/toast in the bottom-right corner.
 * 
 * @param {string} message - Notification text content.
 * @param {string} category - Type: 'success', 'danger', 'warning', 'info'
 */
function showToast(message, category = "info") {
    const toastEl = document.getElementById("liveToast");
    const toastMessage = document.getElementById("toastMessage");
    const toastIcon = document.getElementById("toastIcon");

    if (!toastEl) return;

    // Reset classes
    toastEl.className = "toast align-items-center text-white border-0 bg-dark-slate";
    
    // Choose backgrounds and icons based on category
    let iconClass = "fa-info-circle text-neon-cyan";
    if (category === "success") {
        toastEl.classList.add("bg-dark-slate", "border-start", "border-4", "border-success");
        iconClass = "fa-circle-check text-neon-green";
    } else if (category === "danger") {
        toastEl.classList.add("bg-dark-slate", "border-start", "border-4", "border-danger");
        iconClass = "fa-circle-exclamation text-neon-red";
    } else if (category === "warning") {
        toastEl.classList.add("bg-dark-slate", "border-start", "border-4", "border-warning");
        iconClass = "fa-triangle-exclamation text-neon-amber";
    } else {
        toastEl.classList.add("bg-dark-slate", "border-start", "border-4", "border-info");
        iconClass = "fa-circle-info text-neon-cyan";
    }

    toastMessage.textContent = message;
    toastIcon.className = `fa-solid ${iconClass} fa-lg`;

    // Instantiate and show
    const bsToast = new bootstrap.Toast(toastEl, { delay: 4000 });
    bsToast.show();
}
