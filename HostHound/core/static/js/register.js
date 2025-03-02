document.addEventListener("DOMContentLoaded", function() {

    document.getElementById('registration-form').addEventListener('submit', function (event){
        var password1 = document.getElementById('registration-password1');
            var password2 = document.getElementById('registration-password2');
            var passwordError = document.getElementById('registration-password-error');

            if (password1.value !== password2.value) {
                passwordError.style.display = 'block';
                event.preventDefault();
                return;
            } else {
                passwordError.style.display = 'none';
            }

            var lengthError = document.getElementById('registration-length-error');
            var digitError = document.getElementById('registration-digit-error');
            var specialCharError = document.getElementById('registration-special-char-error');

            var isValid = true;

            if (password1.value.length < 8) {
                lengthError.style.display = 'block';
                isValid = false;
            } else {
                lengthError.style.display = 'none';
            }

            if (!/\d/.test(password1.value)) {
                digitError.style.display = 'block';
                isValid = false;
            } else {
                digitError.style.display = 'none';
            }

            if (!/[!@#$%^&*(),.?":{}|<>]/.test(password1.value)) {
                specialCharError.style.display = 'block';
                isValid = false;
            } else {
                specialCharError.style.display = 'none';
            }

            if (!isValid) {
                event.preventDefault();
            }
    })

    document.getElementById('registration-password1').addEventListener('input', function () {
        var password1 = document.getElementById('registration-password1');
        var lengthError = document.getElementById('registration-length-error');
        var digitError = document.getElementById('registration-digit-error');
        var specialCharError = document.getElementById('registration-special-char-error');

        // Check if password meets criteria as user types
        if (password1.value.length >= 8) {
            lengthError.style.display = 'none';
        } else {
            lengthError.style.display = 'block';
        }

        if (/\d/.test(password1.value)) {
            digitError.style.display = 'none';
        } else {
            digitError.style.display = 'block';
        }

        if (/[!@#$%^&*(),.?":{}|<>]/.test(password1.value)) {
            specialCharError.style.display = 'none';
        } else {
            specialCharError.style.display = 'block';
        }
    });

});