// Projects search with debounce
function setupProjectSearch() {
    const searchInput = document.getElementById('project-search');
    if (!searchInput) return;

    let searchTimeout;
    
    searchInput.addEventListener('input', function() {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            const term = this.value.toLowerCase().trim();
            const rows = document.querySelectorAll('.project-row');
            
            rows.forEach(row => {
                const rowText = Array.from(row.querySelectorAll('td'))
                    .map(td => td.textContent.toLowerCase())
                    .join(' ');
                
                row.style.display = rowText.includes(term) ? '' : 'none';
            });
        }, 300);
    });
}

// Date validation for project forms
function setupDateValidation() {
    const startDateInputs = document.querySelectorAll('input[name="start_date"]');
    const endDateInputs = document.querySelectorAll('input[name="end_date"]');
    
    startDateInputs.forEach((startInput, index) => {
        const endInput = endDateInputs[index];
        if (!endInput) return;
        
        startInput.addEventListener('change', function() {
            if (endInput.value && endInput.value < this.value) {
                alert('End date must be after start date');
                endInput.value = '';
            }
            endInput.min = this.value;
        });
        
        endInput.addEventListener('change', function() {
            if (this.value && this.value < startInput.value) {
                alert('End date must be after start date');
                this.value = '';
            }
        });
    });
}

// Initialize all project page functionality
document.addEventListener('DOMContentLoaded', function() {
    setupProjectSearch();
    setupDateValidation();
    
    // Confirm before deleting projects
    document.querySelectorAll('.delete-project-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to delete this project?')) {
                e.preventDefault();
            }
        });
    });
});