// Three.js 3D Interactive Threat Globe & Mini-Globe Widget for SHIELD_IDS

window.ThreatGlobe = {
    heroScene: null,
    heroCamera: null,
    heroRenderer: null,
    heroGlobeMesh: null,
    heroArcsGroup: null,
    miniScene: null,
    miniCamera: null,
    miniRenderer: null,
    miniGlobeMesh: null,

    // Initialize Hero 3D Threat Globe on Landing Page
    initHeroGlobe(containerId = 'heroGlobeContainer') {
        const container = document.getElementById(containerId);
        if (!container || typeof THREE === 'undefined') return;

        const width = container.clientWidth || 600;
        const height = container.clientHeight || 600;

        // 1. Scene & Camera
        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
        camera.position.z = 280;

        // 2. WebGL Renderer
        const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
        renderer.setSize(width, height);
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        container.appendChild(renderer.domElement);

        // 3. Point Cloud Wireframe Globe Sphere
        const radius = 90;
        const globeGeometry = new THREE.SphereGeometry(radius, 48, 48);

        // Dots / Point Cloud Material
        const pointsMaterial = new THREE.PointsMaterial({
            color: 0x00E5FF,
            size: 1.8,
            transparent: true,
            opacity: 0.75,
            blending: THREE.AdditiveBlending
        });
        const globePoints = new THREE.Points(globeGeometry, pointsMaterial);
        scene.add(globePoints);

        // Inner translucent wireframe shell
        const wireframeMaterial = new THREE.MeshBasicMaterial({
            color: 0x2F6FFF,
            wireframe: true,
            transparent: true,
            opacity: 0.12
        });
        const wireframeMesh = new THREE.Mesh(globeGeometry, wireframeMaterial);
        scene.add(wireframeMesh);

        // Inner glowing core
        const coreGeometry = new THREE.SphereGeometry(radius - 2, 32, 32);
        const coreMaterial = new THREE.MeshBasicMaterial({
            color: 0x05080D,
            transparent: true,
            opacity: 0.95
        });
        const coreMesh = new THREE.Mesh(coreGeometry, coreMaterial);
        scene.add(coreMesh);

        // 4. Particle Field Backdrop
        const particleCount = 400;
        const particlesGeometry = new THREE.BufferGeometry();
        const positions = new Float32Array(particleCount * 3);
        for (let i = 0; i < particleCount * 3; i += 3) {
            positions[i] = (Math.random() - 0.5) * 800;
            positions[i + 1] = (Math.random() - 0.5) * 800;
            positions[i + 2] = (Math.random() - 0.5) * 800;
        }
        particlesGeometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        const particlesMaterial = new THREE.PointsMaterial({
            color: 0x7C93AD,
            size: 1.2,
            transparent: true,
            opacity: 0.4
        });
        const particleSystem = new THREE.Points(particlesGeometry, particlesMaterial);
        scene.add(particleSystem);

        // 5. Threat Traffic Connections (3D Arcs)
        const arcsGroup = new THREE.Group();
        scene.add(arcsGroup);

        // Convert Lat/Long to 3D Coordinates
        function latLongToVector3(lat, lon, r) {
            const phi = (90 - lat) * (Math.PI / 180);
            const theta = (lon + 180) * (Math.PI / 180);
            return new THREE.Vector3(
                -(r * Math.sin(phi) * Math.cos(theta)),
                r * Math.cos(phi),
                r * Math.sin(phi) * Math.sin(theta)
            );
        }

        // Add Sample Threat Connections Arcs
        const threatLocations = [
            { lat: 40.7128, lon: -74.0060 }, // NYC
            { lat: 51.5074, lon: -0.1278 },  // London
            { lat: 35.6762, lon: 139.6503 }, // Tokyo
            { lat: -33.8688, lon: 151.2093 },// Sydney
            { lat: 1.3521, lon: 103.8198 },  // Singapore
            { lat: 55.7558, lon: 37.6173 },  // Moscow
            { lat: 37.7749, lon: -122.4194 } // San Francisco
        ];

        for (let i = 0; i < threatLocations.length; i++) {
            for (let j = i + 1; j < threatLocations.length; j += 2) {
                const start = latLongToVector3(threatLocations[i].lat, threatLocations[i].lon, radius);
                const end = latLongToVector3(threatLocations[j].lat, threatLocations[j].lon, radius);

                // Midpoint raised above globe surface
                const mid = start.clone().add(end).multiplyScalar(0.5);
                const distance = start.distanceTo(end);
                mid.setLength(radius + distance * 0.35);

                const curve = new THREE.QuadraticBezierCurve3(start, mid, end);
                const points = curve.getPoints(40);
                const curveGeometry = new THREE.BufferGeometry().setFromPoints(points);

                const isCritical = (i + j) % 3 === 0;
                const arcColor = isCritical ? 0xFF3B5C : 0x00E5FF;
                const arcMaterial = new THREE.LineBasicMaterial({
                    color: arcColor,
                    transparent: true,
                    opacity: 0.6,
                    linewidth: 1.5
                });

                const arcLine = new THREE.Line(curveGeometry, arcMaterial);
                arcsGroup.add(arcLine);
            }
        }

        // 6. Interactive Drag & Rotate
        let isDragging = false;
        let previousMousePosition = { x: 0, y: 0 };

        container.addEventListener('mousedown', (e) => {
            isDragging = true;
            previousMousePosition = { x: e.clientX, y: e.clientY };
        });

        window.addEventListener('mousemove', (e) => {
            if (!isDragging) return;
            const deltaX = e.clientX - previousMousePosition.x;
            const deltaY = e.clientY - previousMousePosition.y;

            globePoints.rotation.y += deltaX * 0.005;
            globePoints.rotation.x += deltaY * 0.005;
            wireframeMesh.rotation.y += deltaX * 0.005;
            wireframeMesh.rotation.x += deltaY * 0.005;
            arcsGroup.rotation.y += deltaX * 0.005;
            arcsGroup.rotation.x += deltaY * 0.005;

            previousMousePosition = { x: e.clientX, y: e.clientY };
        });

        window.addEventListener('mouseup', () => { isDragging = false; });

        // 7. Animation Loop
        const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

        function animate() {
            requestAnimationFrame(animate);
            if (!prefersReducedMotion && !isDragging) {
                globePoints.rotation.y += 0.0025;
                wireframeMesh.rotation.y += 0.0025;
                arcsGroup.rotation.y += 0.0025;
                particleSystem.rotation.y += 0.0005;
            }
            renderer.render(scene, camera);
        }
        animate();

        // Responsive Resize
        window.addEventListener('resize', () => {
            const w = container.clientWidth;
            const h = container.clientHeight;
            if (w && h) {
                camera.aspect = w / h;
                camera.updateProjectionMatrix();
                renderer.setSize(w, h);
            }
        });

        this.heroScene = scene;
        this.heroGlobeMesh = globePoints;
    },

    // Initialize Dashboard Top Status Bar Mini-Globe Widget
    initMiniGlobe(containerId = 'miniGlobeContainer') {
        const container = document.getElementById(containerId);
        if (!container || typeof THREE === 'undefined') return;

        const size = 44;
        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 100);
        camera.position.z = 40;

        const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
        renderer.setSize(size, size);
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        container.appendChild(renderer.domElement);

        const geometry = new THREE.SphereGeometry(14, 20, 20);
        const pointsMaterial = new THREE.PointsMaterial({
            color: 0x00E5FF,
            size: 1.5,
            transparent: true,
            opacity: 0.8
        });
        const miniGlobe = new THREE.Points(geometry, pointsMaterial);
        scene.add(miniGlobe);

        const wireMaterial = new THREE.MeshBasicMaterial({
            color: 0x2F6FFF,
            wireframe: true,
            transparent: true,
            opacity: 0.25
        });
        const miniWire = new THREE.Mesh(geometry, wireMaterial);
        scene.add(miniWire);

        const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

        function animateMini() {
            requestAnimationFrame(animateMini);
            if (!prefersReducedMotion) {
                miniGlobe.rotation.y += 0.01;
                miniWire.rotation.y += 0.01;
            }
            renderer.render(scene, camera);
        }
        animateMini();

        this.miniGlobeMesh = miniGlobe;
    },

    // Pulse mini globe on new threat alert event
    triggerMiniGlobePulse(isCritical = false) {
        if (!this.miniGlobeMesh) return;
        const originalColor = 0x00E5FF;
        const pulseColor = isCritical ? 0xFF3B5C : 0xFFB020;
        this.miniGlobeMesh.material.color.setHex(pulseColor);

        setTimeout(() => {
            if (this.miniGlobeMesh) {
                this.miniGlobeMesh.material.color.setHex(originalColor);
            }
        }, 1500);
    }
};
