
// ForensicHunter Report JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize charts
    initCharts();
    
    // Initialize collapsible elements
    initCollapsible();
    
    // Initialize filters
    initFilters();
    
    // Initialize theme toggle
    initThemeToggle();
});

function initCharts() {
    // Check if Chart.js is available
    if (typeof Chart === 'undefined') {
        console.warn('Chart.js is not available. Charts will not be rendered.');
        return;
    }
    
    // Severity chart
    const severityCtx = document.getElementById('severityChart');
    if (severityCtx) {
        const severityData = JSON.parse(severityCtx.getAttribute('data-values'));
        const severityLabels = Object.keys(severityData);
        const severityValues = Object.values(severityData);
        const severityColors = {
            'critical': '#e74c3c',
            'high': '#e67e22',
            'medium': '#f1c40f',
            'low': '#3498db',
            'info': '#95a5a6'
        };
        
        new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: severityLabels.map(label => label.charAt(0).toUpperCase() + label.slice(1)),
                datasets: [{
                    data: severityValues,
                    backgroundColor: severityLabels.map(label => severityColors[label.toLowerCase()] || '#95a5a6'),
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                    },
                    title: {
                        display: true,
                        text: 'Résultats par sévérité'
                    }
                }
            }
        });
    }
    
    // Finding types chart
    const typeCtx = document.getElementById('typeChart');
    if (typeCtx) {
        const typeData = JSON.parse(typeCtx.getAttribute('data-values'));
        const typeLabels = Object.keys(typeData);
        const typeValues = Object.values(typeData);
        
        new Chart(typeCtx, {
            type: 'bar',
            data: {
                labels: typeLabels.map(label => label.replace(/_/g, ' ')),
                datasets: [{
                    label: 'Nombre de résultats',
                    data: typeValues,
                    backgroundColor: '#3498db',
                    borderColor: '#2980b9',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: true,
                        text: 'Résultats par type'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        }
                    }
                }
            }
        });
    }
}

function initCollapsible() {
    const collapsibles = document.getElementsByClassName('collapsible');
    
    for (let i = 0; i < collapsibles.length; i++) {
        collapsibles[i].addEventListener('click', function() {
            this.classList.toggle('active');
            const content = this.nextElementSibling;
            
            if (content.style.maxHeight) {
                content.style.maxHeight = null;
            } else {
                content.style.maxHeight = content.scrollHeight + 'px';
            }
        });
    }
}

function initFilters() {
    const filterButtons = document.querySelectorAll('.filter-button');
    const findingCards = document.querySelectorAll('.finding-card');
    
    filterButtons.forEach(button => {
        button.addEventListener('click', function() {
            const filter = this.getAttribute('data-filter');
            
            // Toggle active class
            if (filter === 'all') {
                filterButtons.forEach(btn => btn.classList.remove('active'));
                this.classList.add('active');
            } else {
                document.querySelector('[data-filter="all"]').classList.remove('active');
                this.classList.toggle('active');
            }
            
            // Apply filters
            const activeFilters = Array.from(document.querySelectorAll('.filter-button.active')).map(btn => btn.getAttribute('data-filter'));
            
            findingCards.forEach(card => {
                if (activeFilters.includes('all') || activeFilters.length === 0) {
                    card.style.display = 'block';
                } else {
                    const severity = card.getAttribute('data-severity');
                    const type = card.getAttribute('data-type');
                    
                    if (activeFilters.includes(severity) || activeFilters.includes(type)) {
                        card.style.display = 'block';
                    } else {
                        card.style.display = 'none';
                    }
                }
            });
        });
    });
}

function initThemeToggle() {
    const themeToggle = document.getElementById('themeToggle');
    
    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            document.body.classList.toggle('dark-theme');
            
            const isDarkTheme = document.body.classList.contains('dark-theme');
            themeToggle.textContent = isDarkTheme ? '☀️ Mode clair' : '🌙 Mode sombre';
            
            // Save preference
            localStorage.setItem('darkTheme', isDarkTheme);
            
            // Reinitialize charts with new theme
            initCharts();
        });
        
        // Apply saved preference
        const savedTheme = localStorage.getItem('darkTheme');
        if (savedTheme === 'true') {
            document.body.classList.add('dark-theme');
            themeToggle.textContent = '☀️ Mode clair';
        }
    }
}

// Function to format JSON for display
function formatJSON(json) {
    if (typeof json === 'string') {
        try {
            json = JSON.parse(json);
        } catch (e) {
            return json;
        }
    }
    
    return JSON.stringify(json, null, 2);
}

// Function to toggle visibility of an element
function toggleVisibility(id) {
    const element = document.getElementById(id);
    if (element) {
        element.style.display = element.style.display === 'none' ? 'block' : 'none';
    }
}

// Function to search in findings
function searchFindings() {
    const searchInput = document.getElementById('searchInput');
    const searchTerm = searchInput.value.toLowerCase();
    const findingCards = document.querySelectorAll('.finding-card');
    
    findingCards.forEach(card => {
        const text = card.textContent.toLowerCase();
        if (text.includes(searchTerm)) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
}
