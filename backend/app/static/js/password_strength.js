function calculatePasswordEntropy(password) {
  let entropy = 0;
  if (password.length > 0) {
    let charSetSize = 0;
    let lowerCase = "abcdefghijklmnopqrstuvwxyz";
    let upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let numbers = "0123456789";
    let symbols = "!@#$%^&*()_+~`|}{[]\:;?><,./-=";

    if (password.match(/[a-z]/)) charSetSize += lowerCase.length;
    if (password.match(/[A-Z]/)) charSetSize += upperCase.length;
    if (password.match(/[0-9]/)) charSetSize += numbers.length;
    if (password.match(/[^a-zA-Z0-9\s]/)) charSetSize += symbols.length;

    if (charSetSize > 0) {
      entropy = password.length * (Math.log2(charSetSize));
    }
  }
  return entropy;
}

function checkPasswordStrength() {
  let password = document.getElementById('password').value;
  let entropy = calculatePasswordEntropy(password);
  let strengthText = "Weak";
  if (entropy >= 80) {
    strengthText = "Very strong";
  } else if (entropy >= 60) {
    strengthText = "Strong";
  } else if (entropy >= 40) {
    strengthText = "Mid";
  } else if (entropy >= 20) {
    strengthText = "Weak";
  }

  document.getElementById('passwordStrength').innerText = strengthText;
}