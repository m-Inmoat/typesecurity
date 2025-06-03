// src/interfaces/index.ts
export interface User {
  id: number;
  username: string;
  email: string;
  roles: string[];
}

export interface Task {
  id: number;
  title: string;
  description: string;
  status: 'TODO' | 'IN_PROGRESS' | 'DONE';
  priority: 'LOW' | 'MEDIUM' | 'HIGH';
  dueDate: string;
  ownerId: number;
  assigneeIds: number[];
  createdAt: string;
  updatedAt: string;
}

// Updated AuthResponse
export interface AuthResponse {
  accessToken: string;
  refreshToken?: string;
  id?: number;
  username?: string;
  email?: string;
  roles?: string[];
  type?: string; // Usually "Bearer"
}

export interface LoginRequest {
  username?: string; // Made optional
  password?: string; // Made optional
}

export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
}

export interface TaskRequest {
  title: string;
  description: string;
  status: string;
  priority: string;
  dueDate: string;
  assigneeIds: number[];
}
