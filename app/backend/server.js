const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');

const app = express();
app.use(cors());

const PORT = 5000;

// Utility function to read JSON files asynchronously
const readData = async (filename, res) => {
    try {
        const data = await fs.readFile(path.join(__dirname, 'data', filename), 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error(`Error reading ${filename}:`, error.message);
        res.status(500).json({ error: `Failed to load ${filename}` });
    }
};

// Define API routes
app.get('/api/:category', async (req, res) => {
    const { category } = req.params;
    const validCategories = [
        'logins.json',
        'devices.json',
        'locations.json',
        'compromised.json',
        'suricata_rules.json',
        'reports.json'
    ];

    const filename = `${category}.json`;

    if (!validCategories.includes(filename)) {
        return res.status(404).json({ error: 'Invalid endpoint' });
    }

    const data = await readData(filename, res);
    if (data) res.json(data);
});

// Start the server
app.listen(PORT, () => console.log(`Backend server running on http://localhost:${PORT}`));
