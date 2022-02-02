const apiUrl = 'https://localhost:4567'

function createSpace(name, owner) {
  const data = {name, owner};

  fetch(apiUrl  + '/spaces', {
    method: 'POST',
    credentials: 'include',
    body: JSON.stringify(data),
    headers: {
      'Content-Type': 'application/json'
    }
  })
    .then(response => {
      if (response.ok) {
        return response.json();
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