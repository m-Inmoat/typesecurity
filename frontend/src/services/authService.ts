// src/services/authService.ts
import api from './api';
import type { AuthResponse, LoginRequest, RegisterRequest, User } from '../interfaces';

export const authService = {
  login: async (credentials: LoginRequest): Promise<AuthResponse> => {
    const response = await api.post<AuthResponse>('/auth/login', credentials);
    localStorage.setItem('token', response.data.accessToken);
    return response.data;
  },
  
  register: async (userData: RegisterRequest): Promise<AuthResponse> => {
    const response = await api.post<AuthResponse>('/auth/register', userData);
    return response.data;
  },
  
  logout: (): void => {
    localStorage.removeItem('token');
    localStorage.removeItem('refreshToken');
  },
  
  getCurrentUser: async (): Promise<User | null> => {
    try {
      const response = await api.get<User>('/users/me');
      return response.data;
    } catch (error) {
      return null;
    }
  },
  
  isAuthenticated: (): boolean => {
    return !!localStorage.getItem('token');
  }
};

export default authService;
