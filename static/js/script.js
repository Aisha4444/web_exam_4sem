document.addEventListener('DOMContentLoaded', function() {
    const deleteButtons = document.querySelectorAll('.delete-btn');
    const modal = document.getElementById('delete-modal');
    const confirmDelete = document.getElementById('confirm-delete');
    const cancelDelete = document.getElementById('cancel-delete');
    const bookTitleToDelete = document.getElementById('book-title-to-delete');

    let bookIdToDelete = null;

    deleteButtons.forEach(button => {
        button.addEventListener('click', function() {
            bookIdToDelete = this.dataset.bookId;
            bookTitleToDelete.textContent = this.dataset.bookTitle;
            modal.style.display = 'block';
        });
    });

    confirmDelete.addEventListener('click', function() {
        if (bookIdToDelete) {
            fetch(`/books/${bookIdToDelete}/delete`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCookie('csrf_token')
                }
            })
            .then(response => {
                if (response.redirected) {
                    window.location.href = response.url;
                }
            })
            .catch(error => console.error('Error:', error));
        }
    });

    cancelDelete.addEventListener('click', function() {
        modal.style.display = 'none';
        bookIdToDelete = null;
    });

    window.addEventListener('click', function(event) {
        if (event.target === modal) {
            modal.style.display = 'none';
            bookIdToDelete = null;
        }
    });

    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }
});