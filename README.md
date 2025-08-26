# Cryptera APK Detector

Cryptera APK Detector is a project that provides both a backend API and a frontend interface to analyze APK files. The backend (built with Express) collects metadata, while the frontend (HTML & JavaScript) displays the results.



## Setup and Installation

1. **Clone the Repository**
   
   git clone https://github.com/gourichouksey/cybershield.git
   cd cybershield
   

2. **Install Dependencies**
   Make sure you have Node.js installed. Then run:
   
   npm install
   
   (If your project relies on external dependencies, add them to a `package.json` file.)

3. **Run the Server**
   
   node server.js
   
   The server will start on port 3000 (or the port defined in your environment).

4. **Access the Frontend**
   Open your browser and navigate to:
   
   http://localhost:3000
   
   Click the "Start Scan" button to fetch and display details.

## How to Push Code Changes


1. **Pull Latest Changes**
   
   git pull --rebase origin main
   

2. **Push Your Changes**
   
   git push origin main
   

If you prefer merging over rebasing, you can use:
```bash
git pull origin main
git push origin main