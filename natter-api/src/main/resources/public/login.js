const apiUrl = 'https://localhost:4567';

function login(username, password) {
  // see https://developer.mozilla.org/en-US/docs/Web/API/btoa
  const credentials = 'Basic ' + btoa(username + ':' + password);

  fetch(apiUrl + '/sessions', {
    method: 'POST',
    // we must include credentials to make sure the browser sets cookies for CORS responses
    // UPDATE: chapter 5 uses tokens and we must remove this (p.167)
    // credentials: 'include',
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

          // Chapter 5.2.4 Stop the browser sending cookies
          // document.cookie = 'csrfToken=' + json.token + ';Secure;SameSite=strict';
          localStorage.setItem('token', json.token);

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


