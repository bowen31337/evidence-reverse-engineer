const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const Store = require('electron-store');
const { checkLicense } = require('./src/license');
const store = new Store();

function createWindow() {
  const win = new BrowserWindow({
    width: 1200, height: 800,
    webPreferences: { preload: path.join(__dirname, 'preload.js'), nodeIntegration: true, contextIsolation: false }
  });
  win.loadFile('index.html');
  win.webContents.send('app:ready', { version: app.getVersion() });
}

ipcMain.handle('license:check', async (_e, key) => checkLicense(key));
ipcMain.handle('notes:save', async (_e, note) => { store.set(`note.${note.id}`, note); return true; });
ipcMain.on('telemetry:event', (_e, evt) => require('./src/telemetry').send(evt));
ipcMain.on('open-link', (_e, url) => shell.openExternal(url));
app.setAsDefaultProtocolClient('notekeeper');
app.whenReady().then(createWindow);
