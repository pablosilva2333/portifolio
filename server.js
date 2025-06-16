const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
require('dotenv').config();
const app = express();

// Configuração
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || 'contacts.db';
const SESSION_SECRET = process.env.SESSION_SECRET || 'sua_chave_secreta_muito_segura';

// Middleware
app.use(cors({
    origin: process.env.NODE_ENV === 'production' 
        ? ['https://seu-dominio.com', 'https://www.seu-dominio.com'] 
        : 'http://localhost:3000',
    credentials: true
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configuração da sessão
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
    }
}));

// Database setup
const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Connected to the contacts database.');
});

// Create tables
db.serialize(() => {
    // Tabela de contatos
    db.run(`CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Tabela de usuários
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )`, (err) => {
        if (err) {
            console.error(err.message);
        } else {
            // Inserir usuário admin se não existir
            const adminPassword = process.env.SENHA_ADMIN;
            bcrypt.hash(adminPassword, 10, (err, hash) => {
                if (err) {
                    console.error(err.message);
                    return;
                }
                db.run(`INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)`,
                    ['admin', hash],
                    (err) => {
                        if (err) {
                            console.error(err.message);
                        } else {
                            console.log('Admin user created or already exists');
                        }
                    });
            });
        }
    });
});

// Middleware de autenticação
const requireAuth = (req, res, next) => {
    if (req.session && req.session.user) {
        next();
    } else {
        res.status(401).json({ error: 'Não autorizado' });
    }
};

// Rota de login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Usuário e senha são obrigatórios' });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Erro no servidor' });
        }

        if (!user) {
            return res.status(401).json({ error: 'Usuário ou senha inválidos' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Usuário ou senha inválidos' });
        }

        req.session.user = { id: user.id, username: user.username };
        res.json({ message: 'Login realizado com sucesso' });
    });
});

// Rota de logout
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'Logout realizado com sucesso' });
});

// Rota para verificar status da autenticação
app.get('/api/auth-status', (req, res) => {
    res.json({ 
        authenticated: !!req.session.user,
        user: req.session.user || null
    });
});

// API endpoint to handle form submissions
app.post('/api/submit-form', (req, res) => {
    const { name, email, phone } = req.body;
    
    if (!name || !email || !phone) {
        return res.status(400).json({ error: 'Todos os campos são obrigatórios' });
    }

    const sql = `INSERT INTO contacts (name, email, phone) VALUES (?, ?, ?)`;
    
    db.run(sql, [name, email, phone], function(err) {
        if (err) {
            console.error(err.message);
            res.status(500).json({ error: err.message });
            return;
        }
        
        res.json({
            message: 'Contato salvo com sucesso!',
            contactId: this.lastID
        });
    });
});

// API endpoint to get all contacts (protegido)
app.get('/api/contacts', requireAuth, (req, res) => {
    const sql = `SELECT * FROM contacts ORDER BY created_at DESC`;
    
    db.all(sql, [], (err, rows) => {
        if (err) {
            console.error(err.message);
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// Rota para a página admin (protegida)
app.get('/admin', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Rota para a página principal
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Algo deu errado!' });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 