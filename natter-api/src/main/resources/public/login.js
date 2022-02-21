const apiUrl = 'https://localhost:4567';

function login(username, password) {
  // see https://developer.mozilla.org/en-US/docs/Web/API/btoa
  const credentials = 'Basic ' + btoa(username + ':' + password);

  fetch(apiUrl + '/sessions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': credentials
    }
  })
    .then(res => {
      if (res.ok) {
        res.json().then(json => {
          // note that you cannot use 'HttpOnly' cookie because JS needs to store this token in a cookie (for now)
          // but we can still use 'Secure' and 'SameSite'
          document.cookie = 'csrfToken=' + json.token + ';Secure;SameSite=strict';
          // redirect to the main UI after the authentication is completed
          window.location.replace('/natter.html')
        })
      }
    })
    .catch(error => console.error('Error logging in: ', error));
}

window.addEventListener('load', function (e) {
  document.getElementById('login').addEventListener('submit', processLoginSubmit);
});

function processLoginSubmit(e) {
  e.preventDefault();
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  login(username, password);
  return false;
}


