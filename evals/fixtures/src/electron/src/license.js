const axios = require('axios');
const LICENSE_API = 'https://licensing.notekeeper-app.io/api/v2/validate';
exports.checkLicense = async (key) => {
  const res = await axios.post(LICENSE_API, { key, device: require('os').hostname() });
  return res.data.valid === true;
};
