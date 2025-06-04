// src/services/api.ts
import axios from 'axios';

const API_URL = 'http://localhost:8080/api'; // Ensure this matches backend

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

api.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    const originalRequest = error.config;
    
    if (error.response && error.response.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      try {
        const refreshToken = localStorage.getItem('refreshToken');
        if (refreshToken) {
          // Use the correct endpoint and payload format
          const response = await axios.post(`${API_URL}/auth/refresh`, { refreshToken });
          const { accessToken } = response.data; // Assuming response is { accessToken: "new_token" }
          
          localStorage.setItem('token', accessToken);
          
          originalRequest.headers.Authorization = `Bearer ${accessToken}`;
          return axios(originalRequest);
        } else {
          // No refresh token available, logout or redirect
          authService.logout(); // Call logout from authService
          window.location.href = '/login'; // Or use React Router for navigation
        }
      } catch (refreshError) {
        console.error('Token refresh failed:', refreshError);
        authService.logout(); // Call logout from authService
        window.location.href = '/login'; // Redirect to login
        return Promise.reject(refreshError);
      }
    }
    
    return Promise.reject(error);
  }
);

// Import authService at the end to avoid circular dependencies if api is imported in authService
import authService from './authService';

export default api;
