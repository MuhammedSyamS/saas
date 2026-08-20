const app = require('../src/app');
const { initDb } = require('../src/db');

// Cold start initialization for serverless function
let dbInitialized = false;

module.exports = async (req, res) => {
  if (!dbInitialized) {
    try {
      await initDb();
      dbInitialized = true;
    } catch (err) {
      console.error('Serverless DB initialization error:', err);
    }
  }
  return app(req, res);
};
