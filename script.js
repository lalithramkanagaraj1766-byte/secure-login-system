// 1) Add a Show/Hide button to every password field.
document.querySelectorAll('input[type="password"]').forEach(function (input) {
  var wrap = document.createElement('div');
  wrap.className = 'pw-wrap';
  input.parentNode.insertBefore(wrap, input);
  wrap.appendChild(input);

  var btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'pw-toggle';
  btn.textContent = 'Show';
  btn.setAttribute('aria-label', 'Show or hide password');
  btn.addEventListener('click', function () {
    var hidden = input.type === 'password';
    input.type = hidden ? 'text' : 'password';
    btn.textContent = hidden ? 'Hide' : 'Show';
  });
  wrap.appendChild(btn);
});

// 2) Live password strength meter (the server re-checks everything too).
var meter = document.getElementById('strength');
var field = document.querySelector('[data-strength]');
if (meter && field) {
  field.addEventListener('input', function () {
    var v = field.value, score = 0;
    if (v.length >= 8) score++;
    if (/[a-z]/.test(v) && /[A-Z]/.test(v)) score++;
    if (/\d/.test(v)) score++;
    if (/[^A-Za-z0-9]/.test(v)) score++;
    meter.className = 'strength s' + score;
    meter.textContent = v ? ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'][score] : '';
  });
}
