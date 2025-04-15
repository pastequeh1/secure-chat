const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const CryptoJS = require('crypto-js');
const cors = require('cors');
const path = require('path');
const socket = io('https://secure-chat.onrender.com');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: '*',
        methods: ['GET', 'POST']
    }
});

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const ENCRYPTION_KEY = 'my-secret-key';

// Initialiser SQLite
const db = new sqlite3.Database('./chat.db', (err) => {
    if (err) {
        console.error('Erreur lors de la connexion à SQLite:', err.message);
    } else {
        console.log('Connecté à SQLite');
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT,
                role TEXT DEFAULT 'user',
                friends TEXT DEFAULT '[]',
                banned INTEGER DEFAULT 0,
                sanctions INTEGER DEFAULT 0
            )
        `);
        db.run(`
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT,
                content TEXT,
                timestamp TEXT,
                type TEXT,
                to_user TEXT
            )
        `);
        db.run(`
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reportedBy TEXT,
                reportedUser TEXT,
                category TEXT,
                timestamp TEXT
            )
        `);
    }
});

// Middleware pour vérifier si l'utilisateur est admin
const isAdmin = (req, res, next) => {
    const { username } = req.body;
    db.get('SELECT role FROM users WHERE username = ?', [username], (err, row) => {
        if (err || !row || row.role !== 'admin') {
            return res.status(403).json({ message: 'Accès interdit' });
        }
        next();
    });
};

// Middleware pour vérifier si l'utilisateur est modo
const isModo = (req, res, next) => {
    const { username } = req.body;
    db.get('SELECT role FROM users WHERE username = ?', [username], (err, row) => {
        if (err || !row || (row.role !== 'modo' && row.role !== 'admin')) {
            return res.status(403).json({ message: 'Accès interdit' });
        }
        next();
    });
};

// API Routes
app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT username FROM users WHERE username = ?', [username], (err, row) => {
        if (row) {
            return res.status(400).json({ message: 'Utilisateur déjà existant' });
        }
        const encryptedPassword = CryptoJS.AES.encrypt(password, ENCRYPTION_KEY).toString();
        db.run(
            'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
            [username, encryptedPassword, 'user'],
            (err) => {
                if (err) {
                    return res.status(500).json({ message: 'Erreur serveur' });
                }
                res.json({ message: 'Inscription réussie' });
            }
        );
    });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
        if (err || !row || row.banned) {
            return res.status(401).json({ message: 'Identifiants incorrects ou utilisateur banni' });
        }
        const decryptedPassword = CryptoJS.AES.decrypt(row.password, ENCRYPTION_KEY).toString(CryptoJS.enc.Utf8);
        if (decryptedPassword === password) {
            res.json({ message: 'Connexion réussie', role: row.role });
        } else {
            res.status(401).json({ message: 'Identifiants incorrects' });
        }
    });
});

app.get('/api/friends/:username', (req, res) => {
    db.get('SELECT friends FROM users WHERE username = ?', [req.params.username], (err, row) => {
        if (err || !row) {
            return res.status(500).json({ message: 'Erreur serveur' });
        }
        res.json(JSON.parse(row.friends));
    });
});

app.get('/api/messages/:username', (req, res) => {
    const username = req.params.username;
    db.all(
        `SELECT * FROM messages WHERE type = 'public' OR (type = 'private' AND (user = ? OR to_user = ?))`,
        [username, username],
        (err, rows) => {
            if (err) {
                return res.status(500).json({ message: 'Erreur serveur' });
            }
            res.json(rows);
        }
    );
});

app.post('/api/add-friend', (req, res) => {
    const { user, friend } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [friend], (err, friendRow) => {
        if (err || !friendRow) {
            return res.status(400).json({ message: 'Utilisateur non trouvé' });
        }
        db.get('SELECT friends FROM users WHERE username = ?', [user], (err, userRow) => {
            if (err || !userRow) {
                return res.status(500).json({ message: 'Erreur serveur' });
            }
            let friends = JSON.parse(userRow.friends);
            if (friend === user || friends.includes(friend)) {
                return res.status(400).json({ message: 'Utilisateur non trouvé ou déjà ami' });
            }
            friends.push(friend);
            db.run(
                'UPDATE users SET friends = ? WHERE username = ?',
                [JSON.stringify(friends), user],
                (err) => {
                    if (err) {
                        return res.status(500).json({ message: 'Erreur serveur' });
                    }
                    res.json({ message: 'Ami ajouté' });
                }
            );
        });
    });
});

app.post('/api/report', (req, res) => {
    const { reportedBy, reportedUser, category } = req.body;
    db.get('SELECT username FROM users WHERE username = ?', [reportedUser], (err, row) => {
        if (err || !row) {
            return res.status(400).json({ message: 'Utilisateur non trouvé' });
        }
        db.run(
            'INSERT INTO reports (reportedBy, reportedUser, category, timestamp) VALUES (?, ?, ?, ?)',
            [reportedBy, reportedUser, category, new Date().toISOString()],
            (err) => {
                if (err) {
                    return res.status(500).json({ message: 'Erreur serveur' });
                }
                res.json({ message: 'Signalement envoyé' });
            }
        );
    });
});

app.get('/api/conversations', isAdmin, (req, res) => {
    db.all('SELECT * FROM messages', [], (err, rows) => {
        if (err) {
            return res.status(500).json({ message: 'Erreur serveur' });
        }
        res.json(rows);
    });
});

app.post('/api/sanction', isAdmin, (req, res) => {
    const { username } = req.body;
    db.get('SELECT sanctions FROM users WHERE username = ?', [username], (err, row) => {
        if (err || !row) {
            return res.status(400).json({ message: 'Utilisateur non trouvé' });
        }
        const newSanctions = row.sanctions + 1;
        if (newSanctions >= 3) {
            db.run(
                'UPDATE users SET sanctions = ?, banned = ? WHERE username = ?',
                [newSanctions, 1, username],
                (err) => {
                    if (err) {
                        return res.status(500).json({ message: 'Erreur serveur' });
                    }
                    io.emit('userBanned', username);
                    res.json({ message: `${username} est banni` });
                }
            );
        } else {
            db.run(
                'UPDATE users SET sanctions = ? WHERE username = ?',
                [newSanctions, username],
                (err) => {
                    if (err) {
                        return res.status(500).json({ message: 'Erreur serveur' });
                    }
                    res.json({ message: `${username} a reçu une sanction (${newSanctions}/3)` });
                }
            );
        }
    });
});

app.post('/api/promote', isModo, (req, res) => {
    const { username, role } = req.body;
    db.get('SELECT username FROM users WHERE username = ?', [username], (err, row) => {
        if (err || !row) {
            return res.status(400).json({ message: 'Utilisateur non trouvé' });
        }
        db.run(
            'UPDATE users SET role = ? WHERE username = ?',
            [role, username],
            (err) => {
                if (err) {
                    return res.status(500).json({ message: 'Erreur serveur' });
                }
                io.emit('userPromoted', { username, role });
                res.json({ message: `${username} promu ${role}` });
            }
        );
    });
});

app.post('/api/ban', isModo, (req, res) => {
    const { username } = req.body;
    db.get('SELECT username FROM users WHERE username = ?', [username], (err, row) => {
        if (err || !row) {
            return res.status(400).json({ message: 'Utilisateur non trouvé' });
        }
        db.run(
            'UPDATE users SET banned = ? WHERE username = ?',
            [1, username],
            (err) => {
                if (err) {
                    return res.status(500).json({ message: 'Erreur serveur' });
                }
                io.emit('userBanned', username);
                res.json({ message: `${username} banni` });
            }
        );
    });
});

app.post('/api/unban', isModo, (req, res) => {
    const { username } = req.body;
    db.get('SELECT username FROM users WHERE username = ?', [username], (err, row) => {
        if (err || !row) {
            return res.status(400).json({ message: 'Utilisateur non trouvé' });
        }
        db.run(
            'UPDATE users SET banned = ?, sanctions = ? WHERE username = ?',
            [0, 0, username],
            (err) => {
                if (err) {
                    return res.status(500).json({ message: 'Erreur serveur' });
                }
                io.emit('userUnbanned', username);
                res.json({ message: `${username} débanni` });
            }
        );
    });
});

// Socket.IO pour messages persistants
io.on('connection', (socket) => {
    console.log('Nouvel utilisateur connecté');

    socket.on('userConnected', (username) => {
        socket.username = username;
        socket.broadcast.emit('userStatus', { username, status: 'online' });
    });

    socket.on('publicMessage', (msg) => {
        db.run(
            'INSERT INTO messages (user, content, timestamp, type) VALUES (?, ?, ?, ?)',
            [msg.user, msg.content, msg.timestamp, 'public'],
            (err) => {
                if (err) {
                    console.error('Erreur lors de l\'enregistrement du message public:', err);
                    return;
                }
                io.emit('publicMessage', msg);
            }
        );
    });

    socket.on('privateMessage', (msg) => {
        db.run(
            'INSERT INTO messages (user, content, timestamp, type, to_user) VALUES (?, ?, ?, ?, ?)',
            [msg.from, msg.content, msg.timestamp, 'private', msg.to],
            (err) => {
                if (err) {
                    console.error('Erreur lors de l\'enregistrement du message privé:', err);
                    return;
                }
                io.emit('privateMessage', msg);
            }
        );
    });

    socket.on('disconnect', () => {
        if (socket.username) {
            socket.broadcast.emit('userStatus', { username: socket.username, status: 'offline' });
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Serveur démarré sur http://localhost:${PORT}`);
});