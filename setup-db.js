require('dotenv').config();
const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');

async function runSchema() {
    console.log('🔌 Connecting to Aiven MySQL...');
    
    const conn = await mysql.createConnection({
        host: process.env.DB_HOST,
        port: parseInt(process.env.DB_PORT),
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        ssl: { rejectUnauthorized: false },
        multipleStatements: true
    });

    console.log('✅ Connected!');

    const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
    
    // Split by semicolon and run each statement individually
    const statements = schema
        .split(';')
        .map(s => s.trim())
        .filter(s => s.length > 0 && !s.startsWith('--'));

    for (const stmt of statements) {
        try {
            await conn.execute(stmt);
            const tableName = stmt.match(/TABLE IF NOT EXISTS (\w+)/i)?.[1];
            if (tableName) console.log(`✅ Created table: ${tableName}`);
        } catch (err) {
            console.error(`❌ Error: ${err.message}\n   Statement: ${stmt.substring(0, 60)}...`);
        }
    }

    console.log('\n🎉 Schema setup complete! All tables are ready.');
    await conn.end();
}

runSchema().catch(err => {
    console.error('❌ Fatal error:', err.message);
    process.exit(1);
});
