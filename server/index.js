import express from 'express';
import cors from 'cors';
import Database from 'better-sqlite3';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import dotenv from 'dotenv';

dotenv.config({ path: join(dirname(fileURLToPath(import.meta.url)), '.env') });

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

const db = new Database(join(__dirname, 'golfind.db'));

// CRITICAL: Encryption key MUST be set in environment
if (!process.env.ENCRYPTION_KEY || process.env.ENCRYPTION_KEY.length !== 32) {
  throw new Error('ENCRYPTION_KEY must be exactly 32 characters and set in .env file. Generate one with: openssl rand -hex 16');
}

// CRITICAL: JWT secret MUST be set in environment
if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET must be set in .env file. Generate one with: openssl rand -hex 32');
}

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const JWT_SECRET = process.env.JWT_SECRET;
const SENSITIVE_FIELDS = ['nome', 'cpf', 'nome_mae', 'nome_pai', 'observacao'];

// Whitelists de colunas permitidas por tabela (proteção contra SQL injection)
const COLUMN_WHITELISTS = {
  users: ['id', 'email', 'password', 'created_at'],
  profiles: ['id', 'user_id', 'full_name', 'created_at'],
  user_roles: ['id', 'user_id', 'role', 'created_at'],
  pessoas: ['id', 'nome', 'rg', 'cpf', 'data_nascimento', 'nome_mae', 'nome_pai', 'observacao', 'foto_url', 'residencial', 'created_at', 'updated_at'],
  artigos: ['id', 'numero', 'nome', 'created_at', 'updated_at'],
  condominios: ['id', 'nome', 'created_at'],
  pessoas_artigos: ['id', 'pessoa_id', 'artigo_id', 'created_at'],
  pessoas_condominios: ['id', 'pessoa_id', 'condominio_id', 'data_vinculo', 'created_at', 'updated_at'],
  group_permissions: ['id', 'group_role', 'resource', 'can_create', 'can_read', 'can_update', 'can_delete', 'created_at', 'updated_at'],
};

// Criptografia AES-256-GCM
function encrypt(text) {
  if (!text) return null;
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();
  return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
}

function decrypt(text) {
  if (!text) return null;
  try {
    const parts = text.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encryptedText = parts[2];
    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY), iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    return null;
  }
}

// Validar colunas contra whitelist
function validateColumns(table, columns) {
  const whitelist = COLUMN_WHITELISTS[table];
  if (!whitelist) {
    throw new Error('Invalid table');
  }
  
  for (const col of columns) {
    if (!whitelist.includes(col)) {
      throw new Error(`Invalid column: ${col}`);
    }
  }
  return true;
}

// Middleware de autenticação JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}

// Middleware de verificação de roles
function checkPermission(resource, operation) {
  return (req, res, next) => {
    const userId = req.user.id;
    
    // Buscar role do usuário
    const userRole = db.prepare(`
      SELECT role FROM user_roles WHERE user_id = ?
    `).get(userId);

    if (!userRole) {
      return res.status(403).json({ error: 'User has no assigned role' });
    }

    // Verificar permissão
    const permission = db.prepare(`
      SELECT can_${operation} as has_permission 
      FROM group_permissions 
      WHERE group_role = ? AND resource = ?
    `).get(userRole.role, resource);

    if (!permission || !permission.has_permission) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    next();
  };
}

// Criar tabelas
const createTables = () => {
  // Tabela de usuários
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);

  // Tabela de perfis
  db.exec(`
    CREATE TABLE IF NOT EXISTS profiles (
      id TEXT PRIMARY KEY,
      user_id TEXT UNIQUE NOT NULL,
      full_name TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // Tabela de roles de usuário
  db.exec(`
    CREATE TABLE IF NOT EXISTS user_roles (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'gestor', 'operador', 'visualizador')),
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id),
      UNIQUE(user_id, role)
    )
  `);

  // Tabela de pessoas
  db.exec(`
    CREATE TABLE IF NOT EXISTS pessoas (
      id TEXT PRIMARY KEY,
      nome TEXT NOT NULL,
      rg TEXT NOT NULL,
      cpf TEXT,
      data_nascimento TEXT,
      nome_mae TEXT,
      nome_pai TEXT,
      observacao TEXT,
      foto_url TEXT,
      residencial TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `);

  // Tabela de artigos
  db.exec(`
    CREATE TABLE IF NOT EXISTS artigos (
      id TEXT PRIMARY KEY,
      numero TEXT NOT NULL UNIQUE,
      nome TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `);

  // Tabela de condomínios
  db.exec(`
    CREATE TABLE IF NOT EXISTS condominios (
      id TEXT PRIMARY KEY,
      nome TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);

  // Tabela de relação pessoa-artigo
  db.exec(`
    CREATE TABLE IF NOT EXISTS pessoas_artigos (
      id TEXT PRIMARY KEY,
      pessoa_id TEXT NOT NULL,
      artigo_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (pessoa_id) REFERENCES pessoas(id) ON DELETE CASCADE,
      FOREIGN KEY (artigo_id) REFERENCES artigos(id) ON DELETE CASCADE
    )
  `);

  // Tabela de relação pessoa-condomínio
  db.exec(`
    CREATE TABLE IF NOT EXISTS pessoas_condominios (
      id TEXT PRIMARY KEY,
      pessoa_id TEXT NOT NULL,
      condominio_id TEXT NOT NULL,
      data_vinculo TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (pessoa_id) REFERENCES pessoas(id) ON DELETE CASCADE,
      FOREIGN KEY (condominio_id) REFERENCES condominios(id) ON DELETE CASCADE
    )
  `);

  // Tabela de permissões de grupo
  db.exec(`
    CREATE TABLE IF NOT EXISTS group_permissions (
      id TEXT PRIMARY KEY,
      group_role TEXT NOT NULL CHECK(group_role IN ('admin', 'gestor', 'operador', 'visualizador')),
      resource TEXT NOT NULL,
      can_create INTEGER DEFAULT 0,
      can_read INTEGER DEFAULT 0,
      can_update INTEGER DEFAULT 0,
      can_delete INTEGER DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      UNIQUE(group_role, resource)
    )
  `);
};

// Inicializar dados padrão (apenas permissões)
const initializeDefaultData = async () => {
  // Verificar se já existem permissões
  const existingPermissions = db.prepare('SELECT COUNT(*) as count FROM group_permissions').get();
  
  if (existingPermissions.count === 0) {
    const resources = ['pessoas', 'artigos', 'condominios', 'usuarios'];
    const roles = ['admin', 'gestor', 'operador', 'visualizador'];
    
    const insert = db.prepare(`
      INSERT INTO group_permissions (id, group_role, resource, can_create, can_read, can_update, can_delete, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const insertMany = db.transaction((perms) => {
      for (const perm of perms) {
        insert.run(...perm);
      }
    });

    const permissions = [];
    for (const role of roles) {
      for (const resource of resources) {
        const id = crypto.randomUUID();
        const now = new Date().toISOString();
        permissions.push([
          id,
          role,
          resource,
          role === 'admin' || role === 'gestor' ? 1 : 0,
          1,
          role === 'admin' || role === 'gestor' || role === 'operador' ? 1 : 0,
          role === 'admin' ? 1 : 0,
          now,
          now,
        ]);
      }
    }

    insertMany(permissions);
    console.log('✓ Default permissions initialized');
  }
};

createTables();
initializeDefaultData();

// ============= ENDPOINTS PÚBLICOS (SEM AUTENTICAÇÃO) =============

// Endpoint de login (público)
app.post('/api/auth/signin', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Gerar JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Buscar perfil e role
    const profile = db.prepare('SELECT * FROM profiles WHERE user_id = ?').get(user.id);
    const userRole = db.prepare('SELECT role FROM user_roles WHERE user_id = ?').get(user.id);

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        full_name: profile?.full_name || null,
        role: userRole?.role || null,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint para verificar se sistema precisa de inicialização
app.get('/api/auth/needs-setup', (req, res) => {
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
  res.json({ needsSetup: userCount.count === 0 });
});

// Endpoint para criar primeiro usuário admin (apenas se não existir nenhum usuário)
app.post('/api/auth/setup', async (req, res) => {
  try {
    const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
    
    if (userCount.count > 0) {
      return res.status(400).json({ error: 'Setup already completed' });
    }

    const { email, password, fullName } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const userId = crypto.randomUUID();
    const profileId = crypto.randomUUID();
    const roleId = crypto.randomUUID();
    const hashedPassword = await bcrypt.hash(password, 10);
    const now = new Date().toISOString();

    db.prepare('INSERT INTO users (id, email, password, created_at) VALUES (?, ?, ?, ?)').run(
      userId,
      email,
      hashedPassword,
      now
    );

    db.prepare('INSERT INTO profiles (id, user_id, full_name, created_at) VALUES (?, ?, ?, ?)').run(
      profileId,
      userId,
      fullName || 'Administrador',
      now
    );

    db.prepare('INSERT INTO user_roles (id, user_id, role, created_at) VALUES (?, ?, ?, ?)').run(
      roleId,
      userId,
      'admin',
      now
    );

    res.json({ message: 'First admin user created successfully' });
  } catch (error) {
    console.error('Setup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint para criar novos usuários (requer autenticação de admin)
app.post('/api/auth/create-user', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Verificar se é admin
    const userRole = db.prepare('SELECT role FROM user_roles WHERE user_id = ?').get(userId);
    
    if (!userRole || userRole.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins can create users' });
    }

    const { email, password, fullName, role } = req.body;
    
    if (!email || !password || !role) {
      return res.status(400).json({ error: 'Email, password and role are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const validRoles = ['admin', 'gestor', 'operador', 'visualizador'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    // Verificar se email já existe
    const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const newUserId = crypto.randomUUID();
    const profileId = crypto.randomUUID();
    const roleId = crypto.randomUUID();
    const hashedPassword = await bcrypt.hash(password, 10);
    const now = new Date().toISOString();

    db.prepare('INSERT INTO users (id, email, password, created_at) VALUES (?, ?, ?, ?)').run(
      newUserId,
      email,
      hashedPassword,
      now
    );

    db.prepare('INSERT INTO profiles (id, user_id, full_name, created_at) VALUES (?, ?, ?, ?)').run(
      profileId,
      newUserId,
      fullName || null,
      now
    );

    db.prepare('INSERT INTO user_roles (id, user_id, role, created_at) VALUES (?, ?, ?, ?)').run(
      roleId,
      newUserId,
      role,
      now
    );

    res.json({ id: newUserId, message: 'User created successfully' });
  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============= ENDPOINTS PROTEGIDOS (COM AUTENTICAÇÃO) =============

// Generic GET all - requer permissão de leitura
app.get('/api/:table', authenticateToken, (req, res) => {
  try {
    const { table } = req.params;
    
    // Mapear nome da tabela para recurso de permissão
    let resource = table;
    if (table === 'users' || table === 'profiles' || table === 'user_roles') {
      resource = 'usuarios';
    }

    const userId = req.user.id;
    const userRole = db.prepare('SELECT role FROM user_roles WHERE user_id = ?').get(userId);
    
    if (!userRole) {
      return res.status(403).json({ error: 'User has no assigned role' });
    }

    const permission = db.prepare(
      'SELECT can_read FROM group_permissions WHERE group_role = ? AND resource = ?'
    ).get(userRole.role, resource);

    if (!permission || !permission.can_read) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    let rows = db.prepare(`SELECT * FROM ${table}`).all();
    
    // Descriptografar campos sensíveis para pessoas
    if (table === 'pessoas') {
      rows = rows.map(row => {
        SENSITIVE_FIELDS.forEach(field => {
          if (row[field]) {
            row[field] = decrypt(row[field]);
          }
        });
        return row;
      });
    }
    
    res.json(rows);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Operation failed' });
  }
});

// Generic GET by ID - requer permissão de leitura
app.get('/api/:table/:id', authenticateToken, (req, res) => {
  try {
    const { table, id } = req.params;
    
    let resource = table;
    if (table === 'users' || table === 'profiles' || table === 'user_roles') {
      resource = 'usuarios';
    }

    const userId = req.user.id;
    const userRole = db.prepare('SELECT role FROM user_roles WHERE user_id = ?').get(userId);
    
    if (!userRole) {
      return res.status(403).json({ error: 'User has no assigned role' });
    }

    const permission = db.prepare(
      'SELECT can_read FROM group_permissions WHERE group_role = ? AND resource = ?'
    ).get(userRole.role, resource);

    if (!permission || !permission.can_read) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    let row = db.prepare(`SELECT * FROM ${table} WHERE id = ?`).get(id);
    
    if (!row) {
      return res.status(404).json({ error: 'Not found' });
    }
    
    // Descriptografar campos sensíveis para pessoas
    if (table === 'pessoas') {
      SENSITIVE_FIELDS.forEach(field => {
        if (row[field]) {
          row[field] = decrypt(row[field]);
        }
      });
    }
    
    res.json(row);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Operation failed' });
  }
});

// Generic POST - requer permissão de criação
app.post('/api/:table', authenticateToken, async (req, res) => {
  try {
    const { table } = req.params;
    const data = req.body;
    
    let resource = table;
    if (table === 'users' || table === 'profiles' || table === 'user_roles') {
      resource = 'usuarios';
    }

    const userId = req.user.id;
    const userRole = db.prepare('SELECT role FROM user_roles WHERE user_id = ?').get(userId);
    
    if (!userRole) {
      return res.status(403).json({ error: 'User has no assigned role' });
    }

    const permission = db.prepare(
      'SELECT can_create FROM group_permissions WHERE group_role = ? AND resource = ?'
    ).get(userRole.role, resource);

    if (!permission || !permission.can_create) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    // Validar colunas contra whitelist
    const keys = Object.keys(data);
    validateColumns(table, keys);
    
    // Gerar ID se não fornecido
    if (!data.id) {
      data.id = crypto.randomUUID();
    }
    
    // Hash password para users
    if (table === 'users' && data.password) {
      data.password = await bcrypt.hash(data.password, 10);
    }
    
    // Criptografar campos sensíveis para pessoas
    if (table === 'pessoas') {
      SENSITIVE_FIELDS.forEach(field => {
        if (data[field]) {
          data[field] = encrypt(data[field]);
        }
      });
    }
    
    const values = Object.values(data);
    const placeholders = keys.map(() => '?').join(', ');
    
    db.prepare(`INSERT INTO ${table} (${keys.join(', ')}) VALUES (${placeholders})`).run(...values);
    
    res.json({ id: data.id, message: 'Created successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Operation failed' });
  }
});

// Generic PUT - requer permissão de atualização
app.put('/api/:table/:id', authenticateToken, async (req, res) => {
  try {
    const { table, id } = req.params;
    const data = req.body;
    
    let resource = table;
    if (table === 'users' || table === 'profiles' || table === 'user_roles') {
      resource = 'usuarios';
    }

    const userId = req.user.id;
    const userRole = db.prepare('SELECT role FROM user_roles WHERE user_id = ?').get(userId);
    
    if (!userRole) {
      return res.status(403).json({ error: 'User has no assigned role' });
    }

    const permission = db.prepare(
      'SELECT can_update FROM group_permissions WHERE group_role = ? AND resource = ?'
    ).get(userRole.role, resource);

    if (!permission || !permission.can_update) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    // Validar colunas contra whitelist
    const keys = Object.keys(data).filter(k => k !== 'id');
    validateColumns(table, keys);
    
    // Hash password para users
    if (table === 'users' && data.password) {
      data.password = await bcrypt.hash(data.password, 10);
    }
    
    // Criptografar campos sensíveis para pessoas
    if (table === 'pessoas') {
      SENSITIVE_FIELDS.forEach(field => {
        if (data[field]) {
          data[field] = encrypt(data[field]);
        }
      });
    }
    
    const updates = keys.map(key => `${key} = ?`).join(', ');
    const values = keys.map(key => data[key]);
    values.push(id);
    
    db.prepare(`UPDATE ${table} SET ${updates} WHERE id = ?`).run(...values);
    
    res.json({ message: 'Updated successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Operation failed' });
  }
});

// Generic DELETE - requer permissão de exclusão
app.delete('/api/:table/:id', authenticateToken, (req, res) => {
  try {
    const { table, id } = req.params;
    
    let resource = table;
    if (table === 'users' || table === 'profiles' || table === 'user_roles') {
      resource = 'usuarios';
    }

    const userId = req.user.id;
    const userRole = db.prepare('SELECT role FROM user_roles WHERE user_id = ?').get(userId);
    
    if (!userRole) {
      return res.status(403).json({ error: 'User has no assigned role' });
    }

    const permission = db.prepare(
      'SELECT can_delete FROM group_permissions WHERE group_role = ? AND resource = ?'
    ).get(userRole.role, resource);

    if (!permission || !permission.can_delete) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    db.prepare(`DELETE FROM ${table} WHERE id = ?`).run(id);
    
    res.json({ message: 'Deleted successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Operation failed' });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log('==============================================');
  console.log(`🔒 GolFind Secure Server running on port ${PORT}`);
  console.log('==============================================');
  console.log('✓ JWT Authentication enabled');
  console.log('✓ Role-based authorization active');
  console.log('✓ SQL injection protection active');
  console.log('✓ Field-level encryption enabled');
  console.log('==============================================');
});
