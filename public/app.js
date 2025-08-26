// Frontend JavaScript for Cryptera APK Detector

// Listen for file selection changes on the file input element (#apkUpload)
document.getElementById('apkUpload').addEventListener('change', function(event) {
  const file = event.target.files[0];
  if(file) {
    console.log("Selected file:", file.name);
  }
});

// Listen for click events on the "Scan Now" button (.scan-btn)
document.querySelector('.scan-btn').addEventListener('click', async function() {
  const fileInput = document.getElementById('apkUpload');
  const file = fileInput.files[0];
  
  if (!file) {
    alert("Please select an APK file to scan.");
    return;
  }

  // Disable the button and show a loading message
  document.querySelector('.scan-btn').disabled = true;
  document.querySelector('.results').innerHTML = `<p>Scanning in progress...</p>`;

  // Use FormData to prepare the file for sending in a POST request
  let formData = new FormData();
  formData.append('apk', file);

  try {
    // Send the file to the backend for analysis
    const response = await fetch('/scan', {
      method: 'POST',
      body: formData,
    });

    const result = await response.json();
    // Display the analysis results
    displayResults(result);
  } catch (err) {
    console.error(err);
    document.querySelector('.results').innerHTML = `<p>Error occurred during scanning.</p>`;
  } finally {
    document.querySelector('.scan-btn').disabled = false;
  }
});

// Function to update the RESULT section based on the backend response
function displayResults(data) {
  let html = `<h2>Scan Results</h2>`;
  html += `<p><strong>Package Name:</strong> ${data.metadata.packageName}</p>`;
  html += `<p><strong>Version:</strong> ${data.metadata.version}</p>`;
  html += `<p><strong>File Size:</strong> ${data.metadata.size}</p>`;

  html += `<h3>Permissions:</h3><ul>`;
  data.permissions.forEach(p => {
    html += `<li>${p}</li>`;
  });
  html += `</ul>`;

  html += `<h3>Certificate:</h3>`;
  html += `<p><strong>Issuer:</strong> ${data.certificate.issuer}</p>`;
  html += `<p><strong>Valid:</strong> ${data.certificate.valid}</p>`;

  html += `<h3>ML Prediction:</h3>`;
  html += `<p>${data.mlPrediction}</p>`;

  document.querySelector('.results').innerHTML = html;
}