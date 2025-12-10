const API_URL = 'http://localhost:3001';

// Função para obter o token JWT do localStorage
function getAuthToken(): string | null {
  return localStorage.getItem('golfind_token');
}

// Função para criar headers com autenticação
function getAuthHeaders(): HeadersInit {
  const token = getAuthToken();
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
  };
  
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  
  return headers;
}

// Interfaces
export interface User {
  id: string;
  email: string;
  full_name?: string;
  role?: string;
  password?: string;
  created_at?: string;
}

export interface Profile {
  id: string;
  user_id: string;
  full_name?: string;
  created_at: string;
}

export interface UserRole {
  id: string;
  user_id: string;
  role: string;
  created_at: string;
}

export interface Pessoa {
  id: string;
  nome: string;
  rg: string;
  cpf?: string;
  data_nascimento?: string;
  nome_mae?: string;
  nome_pai?: string;
  observacao?: string;
  foto_url?: string;
  residencial?: string;
  created_at: string;
  updated_at: string;
}

export interface Artigo {
  id: string;
  numero: string;
  nome: string;
  created_at: string;
  updated_at: string;
}

export interface Condominio {
  id: string;
  nome: string;
  created_at: string;
}

export interface PessoaArtigo {
  id: string;
  pessoa_id: string;
  artigo_id: string;
  created_at: string;
}

export interface PessoaCondominio {
  id: string;
  pessoa_id: string;
  condominio_id: string;
  data_vinculo: string;
  created_at: string;
  updated_at?: string;
}

export interface GroupPermission {
  id: string;
  group_role: string;
  resource: string;
  can_create: boolean;
  can_read: boolean;
  can_update: boolean;
  can_delete: boolean;
  created_at: string;
  updated_at: string;
}

// Generic API functions com autenticação JWT
export const api = {
  get: async (endpoint: string) => {
    const response = await fetch(`${API_URL}${endpoint}`, {
      headers: getAuthHeaders(),
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Failed to fetch');
    }
    return response.json();
  },
  
  post: async (endpoint: string, data: any) => {
    const response = await fetch(`${API_URL}${endpoint}`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Failed to post');
    }
    return response.json();
  },
  
  put: async (endpoint: string, data: any) => {
    const response = await fetch(`${API_URL}${endpoint}`, {
      method: 'PUT',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Failed to update');
    }
    return response.json();
  },
  
  delete: async (endpoint: string) => {
    const response = await fetch(`${API_URL}${endpoint}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Failed to delete');
    }
    return response.json();
  },
};

// Auth API (endpoints públicos)
export const authAPI = {
  signIn: async (email: string, password: string) => {
    const response = await fetch(`${API_URL}/api/auth/signin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Login failed');
    }
    return response.json() as Promise<{ token: string; user: User }>;
  },
  
  needsSetup: async () => {
    const response = await fetch(`${API_URL}/api/auth/needs-setup`);
    if (!response.ok) throw new Error('Failed to check setup status');
    return response.json() as Promise<{ needsSetup: boolean }>;
  },
  
  setupFirstUser: async (email: string, password: string, fullName: string) => {
    const response = await fetch(`${API_URL}/api/auth/setup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, fullName }),
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Setup failed');
    }
    return response.json() as Promise<{ message: string }>;
  },

  // Criar novo usuário (requer autenticação de admin)
  createUser: async (email: string, password: string, fullName: string, role: string) => {
    const response = await fetch(`${API_URL}/api/auth/create-user`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ email, password, fullName, role }),
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Failed to create user');
    }
    return response.json() as Promise<{ id: string; message: string }>;
  },
};

// Generic CRUD operations
function createCRUDAPI<T>(tableName: string) {
  return {
    getAll: () => api.get(`/api/${tableName}`) as Promise<T[]>,
    getById: (id: string) => api.get(`/api/${tableName}/${id}`) as Promise<T>,
    create: (data: Partial<T>) => api.post(`/api/${tableName}`, data),
    update: (id: string, data: Partial<T>) => api.put(`/api/${tableName}/${id}`, data),
    delete: (id: string) => api.delete(`/api/${tableName}/${id}`),
  };
}

// Specific APIs
export const usersAPI = createCRUDAPI<User>('users');
export const profilesAPI = createCRUDAPI<Profile>('profiles');
export const userRolesAPI = createCRUDAPI<UserRole>('user_roles');
export const pessoasAPI = createCRUDAPI<Pessoa>('pessoas');
export const artigosAPI = createCRUDAPI<Artigo>('artigos');
export const condominiosAPI = createCRUDAPI<Condominio>('condominios');
export const pessoasArtigosAPI = createCRUDAPI<PessoaArtigo>('pessoas_artigos');
export const pessoasCondominiosAPI = createCRUDAPI<PessoaCondominio>('pessoas_condominios');
export const groupPermissionsAPI = createCRUDAPI<GroupPermission>('group_permissions');

// Utility function to generate UUID (compatível com todos os browsers)
export function generateUUID(): string {
  // Usar crypto.randomUUID se disponível (browsers modernos)
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  
  // Fallback para browsers mais antigos
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}
