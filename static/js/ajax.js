// AJAX Search for Clients and Products
document.addEventListener('DOMContentLoaded', function() {
    // Client Search
    const clientSearch = document.getElementById('client-search');
    if (clientSearch) {
        clientSearch.addEventListener('input', function() {
            const searchTerm = this.value.trim();
            if (searchTerm.length > 2) {
                fetch(`/api/clients/search?q=${encodeURIComponent(searchTerm)}`)
                    .then(response => response.json())
                    .then(data => {
                        const clientRows = document.querySelectorAll('.client-row');
                        clientRows.forEach(row => {
                            const name = row.querySelector('td:first-child').textContent.toLowerCase();
                            const email = row.querySelector('td:nth-child(2)').textContent.toLowerCase();
                            if (name.includes(searchTerm.toLowerCase()) || 
                                email.includes(searchTerm.toLowerCase())) {
                                row.style.display = '';
                            } else {
                                row.style.display = 'none';
                            }
                        });
                    });
            } else {
                // Show all if search term is too short
                document.querySelectorAll('.client-row').forEach(row => {
                    row.style.display = '';
                });
            }
        });
    }

    // Product Search
    const productSearch = document.getElementById('product-search');
    if (productSearch) {
        productSearch.addEventListener('input', function() {
            const searchTerm = this.value.trim();
            if (searchTerm.length > 2) {
                fetch(`/api/products/search?q=${encodeURIComponent(searchTerm)}`)
                    .then(response => response.json())
                    .then(data => {
                        const productCards = document.querySelectorAll('.product-card');
                        productCards.forEach(card => {
                            const name = card.querySelector('h3').textContent.toLowerCase();
                            const desc = card.querySelector('.product-description')?.textContent.toLowerCase() || '';
                            if (name.includes(searchTerm.toLowerCase()) || 
                                desc.includes(searchTerm.toLowerCase())) {
                                card.style.display = '';
                            } else {
                                card.style.display = 'none';
                            }
                        });
                    });
            } else {
                // Show all if search term is too short
                document.querySelectorAll('.product-card').forEach(card => {
                    card.style.display = '';
                });
            }
        });
    }

    // Auto-submit forms with class 'auto-submit'
    document.querySelectorAll('.auto-submit').forEach(form => {
        form.addEventListener('change', function() {
            this.submit();
        });
    });
});