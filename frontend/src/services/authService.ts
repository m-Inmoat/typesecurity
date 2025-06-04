// src/services/authService.ts
import api from './api';
import type { AuthResponse, LoginRequest, RegisterRequest, User } from '../interfaces';

export const authService = {
  login: async (credentials: LoginRequest): Promise<AuthResponse> => {
    const response = await api.post<AuthResponse>('/auth/login', credentials);
    if (response.data.accessToken) { // Standard check
        localStorage.setItem('token', response.data.accessToken);
    }
    if (response.data.refreshToken) { // Store refresh token
        localStorage.setItem('refreshToken', response.data.refreshToken);
    }
    return response.data;
  },
  
  register: async (userData: RegisterRequest): Promise<AuthResponse> => {
    const response = await api.post<AuthResponse>('/auth/register', userData);
    return response.data;
  },
  
  logout: (): void => {
    localStorage.removeItem('token');
    localStorage.removeItem('refreshToken'); // Ensure refresh token is removed
    // Optionally, notify other parts of the app about logout if needed
    // e.g., api.defaults.headers.Authorization = null;
    // window.location.href = '/login'; // Or use react-router for navigation
  },
  
  getCurrentUser: async (): Promise<User | null> => {
    try {
      // This request should now be protected by the Authorization header,
      // and the interceptor in api.ts should handle token refresh if needed.
      const response = await api.get<User>('/users/me');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch current user:', error);
      return null;
    }
  },
  
  isAuthenticated: (): boolean => {
    return !!localStorage.getItem('token');
  }
};

export default authService;
