document.addEventListener("DOMContentLoaded", function() {

    document.getElementById('login-form').addEventListener('submit', function(event) {
        var username = document.getElementById('login-username').value;
        var password = document.getElementById('login-password').value;

        if (!username || !password) {
            alert("Please fill in both username/email and password.");
            event.preventDefault();
        }
    });

});