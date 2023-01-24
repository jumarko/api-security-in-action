const apiUrl = 'https://localhost:4567'

function createSpace(name, owner) {
  const data = {name, owner};

  // NOT USED since Chapter 5.2.4
  // csrtToken cookie is set upon successful login - see login.js
  // const token = getCookie("csrfToken");
  const token = localStorage.getItem('token');

  fetch(apiUrl  + '/spaces', {
    method: 'POST',
    // Chapter 5.2.4 Stop the browser sending cookies
    // credentials: 'include',
    body: JSON.stringify(data),
    headers: {
      'Content-Type': 'application/json',
      // make sure to include anti-CSRF 4 in the header
      // Chapter 5.2.4 Stop the browser sending cookies and use 'Authorization' header instead
      // 'X-CSRF-Token': crsfToken
      'Authorization': 'Bearer ' + token
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

// NOT USED since Chapter 5.2.4
function getCookie(cookieName) {
  const cookieValue = document.cookie.split(';')
    .map(item => item.split('=')
      .map(x => decodeURIComponent(x.trim())))
    .filter(item => item[0] === cookieName)[0];
  if (cookieValue) {
    return cookieValue[1];
  }
}
