// src/services/taskService.ts
import api from './api';
import type { Task, TaskRequest } from '../interfaces';

export const taskService = {
  getAllTasks: async (): Promise<Task[]> => {
    const response = await api.get<Task[]>('/tasks');
    return response.data;
  },
  
  getTaskById: async (id: number): Promise<Task> => {
    const response = await api.get<Task>(`/tasks/${id}`);
    return response.data;
  },
  
  createTask: async (taskData: TaskRequest): Promise<Task> => {
    const response = await api.post<Task>('/tasks', taskData);
    return response.data;
  },
  
  updateTask: async (id: number, taskData: TaskRequest): Promise<Task> => {
    const response = await api.put<Task>(`/tasks/${id}`, taskData);
    return response.data;
  },
  
  deleteTask: async (id: number): Promise<void> => {
    await api.delete(`/tasks/${id}`);
  },
  
  getUserTasks: async (userId: number): Promise<Task[]> => {
    const response = await api.get<Task[]>(`/tasks/user/${userId}`);
    return response.data;
  }
};

export default taskService;
