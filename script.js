async function generateHash() {
    const inputElement = document.getElementById('inputString');
    const saltElement = document.getElementById('saltInput');
    const outputElement = document.getElementById('outputHash');
    const algoElement = document.getElementById('hashAlgo');
    const iterations = parseInt(document.getElementById('iterations').value);

    let inputString = inputElement.value.trim();
    let salt = saltElement.value.trim();
    let hashAlgo = algoElement.value;

    // Default string if input is empty
    if (inputString === '') {
        inputString = 'qwertyuiopasdfghjklzxcvbnm1234567890';
    }

    // Add salt if provided
    if (salt !== '') {
        inputString = inputString + salt;
    }

    let hashedValue = inputString;
    for (let i = 0; i < iterations; i++) {
        if (hashAlgo === 'MD5') {
            hashedValue = md5(hashedValue); // Assuming MD5 comes from a library like CryptoJS
        } else {
            hashedValue = await hashUsingCryptoSubtle(hashedValue, hashAlgo);
        }
    }

    outputElement.value = hashedValue;
}

// Real-time hashing as user types
async function realTimeHash() {
    await generateHash();
}

// Hash using Crypto Subtle (SHA algorithms and others supported by browser)
async function hashUsingCryptoSubtle(input, algorithm) {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const hashBuffer = await crypto.subtle.digest(algorithm, data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
}

// Copy hash to clipboard
function copyToClipboard() {
    const copyText = document.getElementById("outputHash");
    copyText.select();
    document.execCommand("copy");
    alert("Copied the hash: " + copyText.value);
}

// Download hash as text file
function downloadHash() {
    const hashText = document.getElementById("outputHash").value;
    const blob = new Blob([hashText], { type: 'text/plain' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'hash.txt';
    link.click();
}

// Password strength checker (simple rules)
document.getElementById('inputString').addEventListener('input', checkPasswordStrength);

function checkPasswordStrength() {
    const password = document.getElementById('inputString').value;
    const strengthMeter = document.getElementById('strengthMeter');
    const strengthMessage = document.getElementById('strengthMessage');

    let strength = 0;
    if (password.length >= 8) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[\W_]/.test(password)) strength++;

    strengthMeter.style.width = (strength * 20) + '%';

    switch (strength) {
        case 0:
        case 1:
            strengthMeter.style.backgroundColor = 'red';
            strengthMessage.textContent = 'Very Weak';
            break;
        case 2:
            strengthMeter.style.backgroundColor = 'orange';
            strengthMessage.textContent = 'Weak';
            break;
        case 3:
            strengthMeter.style.backgroundColor = 'yellow';
            strengthMessage.textContent = 'Medium';
            break;
        case 4:
            strengthMeter.style.backgroundColor = 'green';
            strengthMessage.textContent = 'Strong';
            break;
        default:
            strengthMeter.style.backgroundColor = 'green';
            strengthMessage.textContent = 'Very Strong';
            break;
    }
}

// Dark mode toggle
function toggleTheme() {
    document.body.classList.toggle('dark-mode');
}

// Show help modal
function showHelp() {
    const modal = document.getElementById('helpModal');
    modal.style.display = 'flex';
}

// Close help modal
function closeHelp() {
    const modal = document.getElementById('helpModal');
    modal.style.display = 'none';
}

// Close modal when clicking outside of it
window.onclick = function(event) {
    const modal = document.getElementById('helpModal');
    if (event.target === modal) {
        modal.style.display = 'none';
    }
}
document.getElementById('copyButton').addEventListener('touchend', copyToClipboard);
document.getElementById('generateHash').addEventListener('touchend', generateHash);
if (window.crypto && window.crypto.subtle) {
    // Proceed with hashing
} else {
    alert('Your browser does not support secure hashing. Please update your browser.');
}

