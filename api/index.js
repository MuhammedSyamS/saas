const app = require('../src/app');
const { initDb } = require('../src/db');

let dbInitialized = false;

module.exports = async (req, res) => {
  if (!dbInitialized) {
    try {
      await Promise.race([
        initDb(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('DB initialization timeout')), 4000))
      ]);
      dbInitialized = true;
    } catch (err) {
      console.warn('Serverless DB initialization fallback:', err.message);
      dbInitialized = true; // Set initialized so subsequent requests do not re-hang
    }
  }
  return app(req, res);
};
