// Ares Docker Agent - JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Auto-refresh dashboard every 30 seconds
    if (window.location.pathname === '/dashboard') {
        setTimeout(function() {
            window.location.reload();
        }, 30000);
    }

    // Confirm dangerous actions
    const dangerForms = document.querySelectorAll('.danger-zone form');
    dangerForms.forEach(function(form) {
        form.addEventListener('submit', function(e) {
            if (!confirm('Are you sure you want to proceed? This action cannot be undone.')) {
                e.preventDefault();
            }
        });
    });

    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert-success');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            alert.style.opacity = '0';
            alert.style.transition = 'opacity 0.5s';
            setTimeout(function() {
                alert.remove();
            }, 500);
        }, 5000);
    });

    // Password strength indicator
    const newPasswordInput = document.getElementById('new_password');
    if (newPasswordInput) {
        newPasswordInput.addEventListener('input', function() {
            const password = this.value;
            const requirements = document.querySelectorAll('.password-requirements li');

            // Check each requirement
            const checks = [
                password.length >= 12,                    // Length
                /[a-z]/.test(password),                  // Lowercase
                /[A-Z]/.test(password),                  // Uppercase
                /\d/.test(password),                      // Number
                /[!@#$%^&*(),.?":{}|<>]/.test(password)  // Special
            ];

            requirements.forEach(function(req, index) {
                if (checks[index]) {
                    req.style.color = '#28a745';
                } else {
                    req.style.color = '#888';
                }
            });
        });
    }

    // Copy public key to clipboard
    const publicKeyCode = document.querySelector('.info-box code');
    if (publicKeyCode) {
        publicKeyCode.style.cursor = 'pointer';
        publicKeyCode.title = 'Click to copy';
        publicKeyCode.addEventListener('click', function() {
            navigator.clipboard.writeText(this.textContent).then(function() {
                const originalText = publicKeyCode.textContent;
                publicKeyCode.textContent = 'Copied!';
                setTimeout(function() {
                    publicKeyCode.textContent = originalText;
                }, 1500);
            });
        });
    }
});
