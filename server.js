const app = require('./src/app');
const { initDb } = require('./src/db');

const PORT = process.env.PORT || 3000;

initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`🏥 VAIDHYAR MANDHIRAM High-Trust Attendance System running at http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error('Failed to initialize database:', err);
});
