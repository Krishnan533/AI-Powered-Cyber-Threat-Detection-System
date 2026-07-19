// Mouse Physics & Custom Cursor System for SHIELD_IDS SOC Command Console

document.addEventListener('DOMContentLoaded', () => {
    // Disable on touch devices or reduced motion preference
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const isTouchDevice = 'ontouchstart' in window || navigator.maxTouchPoints > 0;

    if (prefersReducedMotion || isTouchDevice) {
        return;
    }

    // 1. Create Cursor Elements
    const dot = document.createElement('div');
    dot.className = 'custom-cursor-dot';

    const ring = document.createElement('div');
    ring.className = 'custom-cursor-ring';

    const glow = document.createElement('div');
    glow.className = 'cursor-glow';

    document.body.appendChild(dot);
    document.body.appendChild(ring);
    document.body.appendChild(glow);

    // Target and current position coordinates for spring lerp physics
    let mouseX = window.innerWidth / 2;
    let mouseY = window.innerHeight / 2;
    let ringX = mouseX;
    let ringY = mouseY;

    window.addEventListener('mousemove', (e) => {
        mouseX = e.clientX;
        mouseY = e.clientY;
        dot.style.transform = `translate(${mouseX}px, ${mouseY}px) translate(-50%, -50%)`;
        glow.style.transform = `translate(${mouseX}px, ${mouseY}px) translate(-50%, -50%)`;
    });

    // Spring animation loop for smooth trailing ring
    function animateCursor() {
        ringX += (mouseX - ringX) * 0.15;
        ringY += (mouseY - ringY) * 0.15;
        ring.style.transform = `translate(${ringX}px, ${ringY}px) translate(-50%, -50%)`;
        requestAnimationFrame(animateCursor);
    }
    animateCursor();

    // 2. Cursor Hover Feedback on Interactive Elements
    const interactiveElements = 'a, button, .btn, input, select, .glass-panel, .nav-link, .stat-card';
    document.body.addEventListener('mouseover', (e) => {
        if (e.target.closest(interactiveElements)) {
            ring.style.width = '50px';
            ring.style.height = '50px';
            ring.style.borderColor = 'rgba(0, 229, 255, 0.6)';
            ring.style.backgroundColor = 'rgba(0, 229, 255, 0.05)';
        }
    });

    document.body.addEventListener('mouseout', (e) => {
        if (e.target.closest(interactiveElements)) {
            ring.style.width = '36px';
            ring.style.height = '36px';
            ring.style.borderColor = 'rgba(0, 229, 255, 0.25)';
            ring.style.backgroundColor = 'transparent';
        }
    });

    // 3. Magnetic CTA Buttons Effect
    const magneticBtns = document.querySelectorAll('.btn-neon-cyan, .btn-magnetic');
    magneticBtns.forEach((btn) => {
        btn.addEventListener('mousemove', (e) => {
            const rect = btn.getBoundingClientRect();
            const relX = e.clientX - rect.left - rect.width / 2;
            const relY = e.clientY - rect.top - rect.height / 2;
            btn.style.transform = `translate(${relX * 0.25}px, ${relY * 0.25}px)`;
        });

        btn.addEventListener('mouseleave', () => {
            btn.style.transform = 'translate(0px, 0px)';
        });
    });

    // 4. Click Ripple Effect
    document.addEventListener('click', (e) => {
        const targetBtn = e.target.closest('.btn, .glass-panel, .nav-link');
        if (!targetBtn) return;

        const ripple = document.createElement('span');
        ripple.style.position = 'absolute';
        ripple.style.borderRadius = '50%';
        ripple.style.background = 'rgba(0, 229, 255, 0.4)';
        ripple.style.transform = 'scale(0)';
        ripple.style.animation = 'ripple-animation 0.6s linear';
        ripple.style.pointerEvents = 'none';

        const rect = targetBtn.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        ripple.style.width = ripple.style.height = `${size}px`;
        ripple.style.left = `${e.clientX - rect.left - size / 2}px`;
        ripple.style.top = `${e.clientY - rect.top - size / 2}px`;

        if (getComputedStyle(targetBtn).position === 'static') {
            targetBtn.style.position = 'relative';
        }

        targetBtn.appendChild(ripple);
        setTimeout(() => ripple.remove(), 600);
    });
});

// Inject Ripple Animation CSS
const rippleStyle = document.createElement('style');
rippleStyle.textContent = `
@keyframes ripple-animation {
    to {
        transform: scale(2.5);
        opacity: 0;
    }
}
`;
document.head.appendChild(rippleStyle);
