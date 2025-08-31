// --- Dépendances ---
// IMPORTANT: npm install cloudinary multer-storage-cloudinary
// -----------------------------------------------------------

const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('cloudinary').v2;
const mysql = require('mysql2/promise');
const { randomUUID } = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'local-secret-key';

// --- Configuration de Cloudinary ---
// Ces variables seront lues depuis l'environnement sur Render
cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
  api_key: process.env.CLOUDINARY_API_KEY, 
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'studyhub_uploads', // Nom du dossier sur Cloudinary
    resource_type: 'auto', // Laisse Cloudinary déterminer le type de fichier
  },
});

const upload = multer({ storage: storage });

// --- Middlewares ---
app.use(cors());
app.use(express.json());

// --- Connexion à la base de données MySQL ---
const dbPool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',      
    user: process.env.DB_USER || 'root',           
    password: process.env.DB_PASSWORD || '',           
    database: process.env.DB_DATABASE || 'study_hub',
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// --- Middleware pour vérifier le Token JWT ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// =================================================================
// --- ROUTES API ---
// =================================================================

// --- Fichiers ---
app.get('/api/files', authenticateToken, async (req, res) => {
    try {
        const [rows] = await dbPool.query('SELECT id, name, path, size, uploaderId, uploaderName, createdAt FROM files ORDER BY createdAt DESC');
        res.json(rows);
    } catch (error) {
        res.status(500).json({ error: "Erreur lors de la récupération des fichiers." });
    }
});

app.post('/api/files', authenticateToken, upload.single('file'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "Aucun fichier envoyé." });
    
    const { originalname, size, path: cloudinaryUrl } = req.file;
    const { uid, displayName } = req.user;
    
    try {
        const sql = 'INSERT INTO files (name, path, size, uploaderId, uploaderName) VALUES (?, ?, ?, ?, ?)';
        await dbPool.query(sql, [originalname, cloudinaryUrl, size, uid, displayName]);
        
        io.emit('update_dashboard');
        res.status(201).json({ message: 'Fichier uploadé avec succès.' });
    } catch (error) {
        res.status(500).json({ error: "Erreur lors de l'enregistrement du fichier." });
    }
});


// --- Le reste du serveur reste inchangé ---
// ... (Copiez et collez le reste du code de votre `server.js` ici, depuis la route `/api/stats` jusqu'à la fin) ...

app.post('/api/register', async (req, res) => {
    const { displayName, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const uid = randomUUID();
        const sql = 'INSERT INTO users (uid, displayName, email, password) VALUES (?, ?, ?, ?)';
        await dbPool.query(sql, [uid, displayName, email, hashedPassword]);
        res.status(201).json({ message: "Inscription réussie ! En attente d'approbation par un administrateur." });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: "Cet email est déjà utilisé." });
        }
        res.status(500).json({ error: "Erreur lors de l'inscription." });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [rows] = await dbPool.query('SELECT * FROM users WHERE email = ?', [email]);
        const user = rows[0];

        if (!user) return res.status(400).json({ error: "Identifiants incorrects." });
        if (user.status !== 'approved') return res.status(403).json({ error: "Votre compte n'est pas encore approuvé ou a été banni." });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: "Identifiants incorrects." });

        const accessToken = jwt.sign({ uid: user.uid, role: user.role, displayName: user.displayName }, JWT_SECRET, { expiresIn: '8h' });
        res.json({ accessToken });
    } catch (error) {
        res.status(500).json({ error: "Erreur serveur." });
    }
});

app.get('/api/me', authenticateToken, async (req, res) => {
    try {
        const [rows] = await dbPool.query('SELECT uid, displayName, email, role, status FROM users WHERE uid = ?', [req.user.uid]);
        if (rows.length === 0) return res.status(404).json({ error: "Utilisateur non trouvé." });
        res.json(rows[0]);
    } catch (error) {
        res.status(500).json({ error: "Erreur serveur." });
    }
});

app.put('/api/me/update', authenticateToken, async (req, res) => {
    const { uid } = req.user;
    const { displayName, email, newPassword } = req.body;
    let setClauses = [];
    let queryParams = [];
    if (displayName) {
        setClauses.push('displayName = ?');
        queryParams.push(displayName);
    }
    if (email) {
        try {
            const [existingUser] = await dbPool.query('SELECT uid FROM users WHERE email = ? AND uid != ?', [email, uid]);
            if (existingUser.length > 0) {
                return res.status(409).json({ error: "Cet email est déjà utilisé par un autre compte." });
            }
            setClauses.push('email = ?');
            queryParams.push(email);
        } catch(e) {
             return res.status(500).json({ error: "Erreur serveur lors de la vérification de l'email." });
        }
    }
    if (newPassword) {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        setClauses.push('password = ?');
        queryParams.push(hashedPassword);
    }
    if (setClauses.length === 0) {
        return res.status(400).json({ error: "Aucune information à mettre à jour." });
    }
    const sql = `UPDATE users SET ${setClauses.join(', ')} WHERE uid = ?`;
    queryParams.push(uid);
    try {
        await dbPool.query(sql, queryParams);
        const [rows] = await dbPool.query('SELECT uid, displayName, email, role FROM users WHERE uid = ?', [uid]);
        const updatedUser = rows[0];
        const accessToken = jwt.sign(
            { uid: updatedUser.uid, role: updatedUser.role, displayName: updatedUser.displayName },
            JWT_SECRET,
            { expiresIn: '8h' }
        );
        res.json({ message: 'Profil mis à jour avec succès.', accessToken });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de la mise à jour du profil.' });
    }
});

app.get('/api/users', authenticateToken, async(req, res) => {
    try {
        const [rows] = await dbPool.query('SELECT uid, displayName FROM users WHERE status = ?', ['approved']);
        res.json(rows);
    } catch (error) {
        res.status(500).json({ error: "Erreur lors de la récupération des utilisateurs." });
    }
});

app.get('/api/events', async (req, res) => {
    try {
        const [rows] = await dbPool.query('SELECT * FROM events ORDER BY createdAt DESC');
        res.json(rows);
    } catch (error) {
        res.status(500).json({ error: "Erreur lors de la récupération des événements." });
    }
});

app.get('/api/files/latest', authenticateToken, async (req, res) => {
    try {
        const [rows] = await dbPool.query('SELECT id, name, uploaderName, createdAt FROM files ORDER BY createdAt DESC LIMIT 3');
        res.json(rows);
    } catch (error) {
        res.status(500).json({ error: "Erreur lors de la récupération des derniers fichiers." });
    }
});

app.get('/api/stats', authenticateToken, async (req, res) => {
    try {
        const [userRows] = await dbPool.query("SELECT COUNT(*) as userCount FROM users WHERE status = 'approved'");
        const [fileRows] = await dbPool.query("SELECT COUNT(*) as fileCount FROM files");

        res.json({
            userCount: userRows[0].userCount,
            fileCount: fileRows[0].fileCount
        });
    } catch (error) {
        res.status(500).json({ error: "Erreur lors de la récupération des statistiques." });
    }
});

const authorizeAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    next();
};

app.get('/api/admin/users', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const [rows] = await dbPool.query('SELECT id, uid, displayName, email, role, status, createdAt FROM users ORDER BY createdAt DESC');
        res.json(rows);
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur.'});
    }
});

app.put('/api/admin/users/:uid/status', authenticateToken, authorizeAdmin, async (req, res) => {
    const { status } = req.body;
    try {
        await dbPool.query('UPDATE users SET status = ? WHERE uid = ?', [status, req.params.uid]);
        io.emit('update_dashboard');
        res.json({ message: 'Statut mis à jour.'});
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur.'});
    }
});

app.post('/api/admin/events', authenticateToken, authorizeAdmin, async (req, res) => {
    const { title, content } = req.body;
    try {
        await dbPool.query('INSERT INTO events (title, content) VALUES (?, ?)', [title, content]);
        io.emit('update_dashboard');
        res.status(201).json({ message: 'Événement ajouté.'});
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur.'});
    }
});

app.delete('/api/admin/events/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        await dbPool.query('DELETE FROM events WHERE id = ?', [req.params.id]);
        io.emit('update_dashboard');
        res.json({ message: 'Événement supprimé.'});
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur.'});
    }
});

io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) {
        return next(new Error("Authentication error"));
    }
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return next(new Error("Authentication error"));
        socket.user = user;
        next();
    });
});

io.on('connection', (socket) => {
    console.log('Un utilisateur authentifié est connecté:', socket.user.displayName);
    
    io.emit('update_online_users', io.sockets.sockets.size);

    socket.on('join_chat', async (chatId) => {
        socket.join(chatId);
        try {
            const [messages] = await dbPool.query(
                'SELECT * FROM messages WHERE chatId = ? ORDER BY createdAt ASC LIMIT 50',
                [chatId]
            );
            socket.emit('chat_history', messages);
        } catch (error) {
            console.error("Erreur lors de la récupération de l'historique du chat:", error);
        }
    });

    socket.on('send_message', async (data) => {
        const { chatId, senderId, senderName, text } = data;
        if (!text || text.trim() === '') return;
        try {
            const sql = 'INSERT INTO messages (chatId, senderId, senderName, text) VALUES (?, ?, ?, ?)';
            const [result] = await dbPool.query(sql, [chatId, senderId, senderName, text]);
            const [rows] = await dbPool.query('SELECT * FROM messages WHERE id = ?', [result.insertId]);
            io.to(chatId).emit('receive_message', rows[0]);
        } catch (error) {
            console.error("Erreur lors de l'envoi du message:", error);
        }
    });

    socket.on('disconnect', () => {
        console.log('Un utilisateur s\'est déconnecté:', socket.user.displayName);
        io.emit('update_online_users', io.sockets.sockets.size);
    });
});


server.listen(PORT, () => {
    console.log(`✅ Serveur démarré sur http://localhost:${PORT}`);
});

