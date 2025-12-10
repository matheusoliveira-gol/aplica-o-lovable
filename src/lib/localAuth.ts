import { authAPI } from './api';

// Sessão de usuário
const SESSION_KEY = 'golfind_session';
const TOKEN_KEY = 'golfind_token';

export interface Session {
  user: {
    id: string;
    email: string;
    full_name?: string;
    role?: string;
  };
  token: string;
}

// Obter sessão atual
export function getSession(): Session | null {
  const sessionData = localStorage.getItem(SESSION_KEY);
  if (!sessionData) return null;
  return JSON.parse(sessionData);
}

// Criar sessão
export function setSession(user: { id: string; email: string; full_name?: string; role?: string }, token: string) {
  const session: Session = { user, token };
  localStorage.setItem(SESSION_KEY, JSON.stringify(session));
  localStorage.setItem(TOKEN_KEY, token);
}

// Remover sessão
export function clearSession() {
  localStorage.removeItem(SESSION_KEY);
  localStorage.removeItem(TOKEN_KEY);
}

// Obter token JWT
export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

// Login
export async function signIn(email: string, password: string) {
  const result = await authAPI.signIn(email, password);
  setSession(result.user, result.token);
  return result;
}

// Setup - criar primeiro usuário
export async function setupFirstUser(email: string, password: string, fullName: string) {
  return await authAPI.setupFirstUser(email, password, fullName);
}

// Verificar se sistema precisa de setup
export async function needsSetup() {
  return await authAPI.needsSetup();
}

// Logout
export async function signOut() {
  clearSession();
}

// Verificar se está autenticado
export function isAuthenticated(): boolean {
  return getSession() !== null;
}

// Obter usuário atual
export function getCurrentUser() {
  const session = getSession();
  return session?.user || null;
}
