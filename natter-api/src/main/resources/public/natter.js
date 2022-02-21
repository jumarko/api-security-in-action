const apiUrl = 'https://localhost:4567'

function createSpace(name, owner) {
  const data = {name, owner};
  // csrtToken cookie is set upon successful login - see login.js
  const crsfToken = getCookie("csrfToken");

  fetch(apiUrl  + '/spaces', {
    method: 'POST',
    credentials: 'include',
    body: JSON.stringify(data),
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
    .then(json => console.log('Created space: ', json.name, json.uri))
    .catch(error => console.error('Error: ', error));
}

window.addEventListener('load', function(e) {
  document.getElementById('createSpace').addEventListener('submit', processFormSubmit);
})

function processFormSubmit(e) {
  e.preventDefault(); // suppres default browser behavior (submitting the form)
  const spaceName = document.getElementById('spaceName').value;
  const owner = document.getElementById('owner').value;
  createSpace(spaceName, owner);
  return false; // prevent further event processing
}

function getCookie(cookieName) {
  const cookieValue = document.cookie.split(';')
    .map(item => item.split('=')
      .map(x => decodeURIComponent(x.trim())))
    .filter(item => item[0] === cookieName)[0];
  if (cookieValue) {
    return cookieValue[1];
  }
}
