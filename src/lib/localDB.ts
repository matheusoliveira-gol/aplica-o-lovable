import Dexie, { Table } from 'dexie';

// Interfaces para as tabelas
export interface User {
  id: string;
  email: string;
  password: string;
  created_at: string;
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

// Banco de dados local
class LocalDatabase extends Dexie {
  users!: Table<User>;
  profiles!: Table<Profile>;
  user_roles!: Table<UserRole>;
  pessoas!: Table<Pessoa>;
  artigos!: Table<Artigo>;
  condominios!: Table<Condominio>;
  pessoas_artigos!: Table<PessoaArtigo>;
  pessoas_condominios!: Table<PessoaCondominio>;
  group_permissions!: Table<GroupPermission>;

  constructor() {
    super('GolFindDB');
    this.version(1).stores({
      users: 'id, email',
      profiles: 'id, user_id',
      user_roles: 'id, user_id',
      pessoas: 'id, nome, rg, cpf',
      artigos: 'id, numero',
      condominios: 'id, nome',
      pessoas_artigos: 'id, pessoa_id, artigo_id',
      pessoas_condominios: 'id, pessoa_id, condominio_id',
      group_permissions: 'id, group_role, resource',
    });
  }
}

export const db = new LocalDatabase();

// Função para gerar UUID
export function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// Inicializar dados padrão
export async function initializeDefaultData() {
  const userCount = await db.users.count();
  
  if (userCount === 0) {
    // Criar usuário admin padrão
    const userId = generateUUID();
    const profileId = generateUUID();
    const roleId = generateUUID();
    
    await db.users.add({
      id: userId,
      email: 'admin@golfind.com',
      password: 'admin123', // Em produção, use hash
      created_at: new Date().toISOString(),
    });

    await db.profiles.add({
      id: profileId,
      user_id: userId,
      full_name: 'Administrador',
      created_at: new Date().toISOString(),
    });

    await db.user_roles.add({
      id: roleId,
      user_id: userId,
      role: 'admin',
      created_at: new Date().toISOString(),
    });

    // Criar permissões padrão para admin
    const resources = ['pessoas', 'artigos', 'condominios', 'usuarios'];
    const roles = ['admin', 'gestor', 'operador', 'visualizador'];
    
    for (const role of roles) {
      for (const resource of resources) {
        await db.group_permissions.add({
          id: generateUUID(),
          group_role: role,
          resource,
          can_create: role === 'admin' || role === 'gestor',
          can_read: true,
          can_update: role === 'admin' || role === 'gestor' || role === 'operador',
          can_delete: role === 'admin',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        });
      }
    }
  }
}

// Inicializar na primeira carga
initializeDefaultData();
