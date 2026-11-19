// Local development: `npm start` serves the API and the website together on http://localhost:3000
import app from './app.js';
const port = +process.env.PORT || 3000;
app.listen(port, () => console.log(`Brokeo running on http://localhost:${port}`));
