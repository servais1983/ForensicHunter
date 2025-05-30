// Fonctions utilitaires
function showAlert(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type}`;
    alertDiv.textContent = message;
    
    const container = document.querySelector('.main-content');
    container.insertBefore(alertDiv, container.firstChild);
    
    setTimeout(() => {
        alertDiv.remove();
    }, 5000);
}

// Gestion des formulaires
function handleFormSubmit(event) {
    event.preventDefault();
    const form = event.target;
    const formData = new FormData(form);
    
    // Validation basique
    let isValid = true;
    formData.forEach((value, key) => {
        if (!value && form.elements[key].hasAttribute('required')) {
            isValid = false;
            showAlert(`Le champ ${key} est requis`, 'danger');
        }
    });
    
    if (!isValid) return;
    
    // Envoi du formulaire
    fetch(form.action, {
        method: form.method,
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showAlert(data.message, 'success');
            form.reset();
        } else {
            showAlert(data.message, 'danger');
        }
    })
    .catch(error => {
        showAlert('Une erreur est survenue', 'danger');
        console.error('Erreur:', error);
    });
}

// Gestion des tableaux
function initDataTable(tableId) {
    const table = document.getElementById(tableId);
    if (!table) return;
    
    const searchInput = document.createElement('input');
    searchInput.type = 'text';
    searchInput.placeholder = 'Rechercher...';
    searchInput.className = 'form-control';
    
    table.parentNode.insertBefore(searchInput, table);
    
    searchInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        const rows = table.getElementsByTagName('tr');
        
        for (let i = 1; i < rows.length; i++) {
            const row = rows[i];
            const cells = row.getElementsByTagName('td');
            let found = false;
            
            for (let cell of cells) {
                if (cell.textContent.toLowerCase().includes(searchTerm)) {
                    found = true;
                    break;
                }
            }
            
            row.style.display = found ? '' : 'none';
        }
    });
}

// Gestion des onglets
function initTabs() {
    const tabLinks = document.querySelectorAll('.nav-item a');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            
            // Désactive tous les onglets
            tabLinks.forEach(l => l.classList.remove('active'));
            tabContents.forEach(c => c.style.display = 'none');
            
            // Active l'onglet sélectionné
            link.classList.add('active');
            const targetId = link.getAttribute('href').substring(1);
            document.getElementById(targetId).style.display = 'block';
        });
    });
}

// Initialisation
document.addEventListener('DOMContentLoaded', () => {
    // Initialisation des formulaires
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', handleFormSubmit);
    });
    
    // Initialisation des tableaux
    document.querySelectorAll('.table').forEach(table => {
        initDataTable(table.id);
    });
    
    // Initialisation des onglets
    initTabs();
}); 