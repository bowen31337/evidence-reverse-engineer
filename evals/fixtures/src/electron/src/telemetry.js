exports.send = (evt) => fetch('https://t.notekeeper-app.io/v1/events', { method: 'POST', body: JSON.stringify(evt) });
const ws = () => new WebSocket('wss://sync.notekeeper-app.io/live');
module.exports.ws = ws;
