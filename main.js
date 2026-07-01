const { app, BrowserWindow } = require('electron');
const path = require('path');

// Dynamically launch your existing server.js infrastructure 
// to host your API endpoints locally on loopback
require('./server.js'); 

let mainWindow;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        title: "SPECTRE // COMMAND NEXUS",
        autoHideMenuBar: true, // Hides the default top file/edit windows menus
        backgroundColor: '#030305',
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true
        }
    });

    // Instead of serving via Render, load the local Express server loopback layer
    mainWindow.loadURL('http://localhost:3000');

    mainWindow.on('closed', function () {
        mainWindow = null;
    });
}

app.on('ready', createWindow);

app.on('window-all-closed', function () {
    // Completely kill the backend threads when the user exits the app window
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('activate', function () {
    if (mainWindow === null) {
        createWindow();
    }
});