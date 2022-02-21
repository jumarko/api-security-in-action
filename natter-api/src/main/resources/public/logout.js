const apiUrl = 'https://localhost:4567'

function logout() {
  const crsfToken = getCookie("csrfToken");

  fetch(apiUrl  + '/sessions', {
    method: 'DELETE',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      // make sure to include anti-CSRF token in the header
      'X-CSRF-Token': crsfToken
    }
  })
    .then(response => {
      if (response.ok) {
        return response.json();
      } else if (response.status === 401) {
        // redirect unauthorized users to the Login UI
        window.location.replace('/login.html');
      } else {
        throw Error(response.statusText + ": " + response.text().then(alert));
      }
    })
    .then(json => alert('Logged out.'))
    .catch(error => console.error('Error: ', error));
}

window.addEventListener('load', function(e) {
  // https://www.w3schools.com/jsref/met_element_addeventlistener.asp
  document.getElementById('logout-button').addEventListener('click', logout);
});

function getCookie(cookieName) {
  const cookieValue = document.cookie.split(';')
    .map(item => item.split('=')
      .map(x => decodeURIComponent(x.trim())))
    .filter(item => item[0] === cookieName)[0];
  if (cookieValue) {
    return cookieValue[1];
  }
}
