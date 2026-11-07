const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('noteApi', {
  checkLicense: (key) => ipcRenderer.invoke('license:check', key),
  save: (note) => ipcRenderer.invoke('notes:save', note),
  exportPdf: (id) => ipcRenderer.invoke('notes:export-pdf', id),
  track: (evt) => ipcRenderer.send('telemetry:event', evt),
});
