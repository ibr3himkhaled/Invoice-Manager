// Close flash messages
document.addEventListener('DOMContentLoaded', function() {
    // Close flash messages
    document.querySelectorAll('.close-flash').forEach(button => {
        button.addEventListener('click', function() {
            this.parentElement.style.opacity = '0';
            setTimeout(() => {
                this.parentElement.remove();
            }, 300);
        });
    });
    
    // Auto-hide flash messages after 5 seconds
    setTimeout(() => {
        document.querySelectorAll('.flash-message').forEach(msg => {
            msg.style.opacity = '0';
            setTimeout(() => {
                msg.remove();
            }, 300);
        });
    }, 5000);
    
    // Confirm before delete actions
    document.querySelectorAll('[data-confirm]').forEach(link => {
        link.addEventListener('click', function(e) {
            if (!confirm(this.dataset.confirm || 'Are you sure you want to delete this item?')) {
                e.preventDefault();
            }
        });
    });
    // Enhanced Project Search Functionality
document.addEventListener('DOMContentLoaded', function() {
    const projectSearch = document.getElementById('project-search');
    if (projectSearch) {
        projectSearch.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            const rows = document.querySelectorAll('.project-row');
            
            rows.forEach(row => {
                const cells = row.querySelectorAll('td');
                let rowText = '';
                
                cells.forEach(cell => {
                    rowText += cell.textContent.toLowerCase() + ' ';
                });
                
                if (rowText.includes(searchTerm)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        });
    }

    // Date Picker Enhancements
    const dateInputs = document.querySelectorAll('input[type="date"]');
    dateInputs.forEach(input => {
        // Set min date to today for start dates
        if (input.name === 'start_date') {
            input.min = new Date().toISOString().split('T')[0];
        }
        
        // Validate end date is after start date
        if (input.name === 'end_date') {
            input.addEventListener('change', function() {
                const startDate = document.querySelector('input[name="start_date"]');
                if (startDate && startDate.value && this.value) {
                    if (new Date(this.value) < new Date(startDate.value)) {
                        alert('End date must be after start date');
                        this.value = '';
                    }
                }
            });
        }
    });

    // Budget Input Validation
    const budgetInputs = document.querySelectorAll('input[name="budget"]');
    budgetInputs.forEach(input => {
        input.addEventListener('blur', function() {
            if (this.value && parseFloat(this.value) < 0) {
                alert('Budget cannot be negative');
                this.value = '';
            }
        });
    });
});
});