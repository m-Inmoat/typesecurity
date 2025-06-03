// src/App.tsx
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme, CssBaseline } from '@mui/material';
import { AuthProvider } from './contexts/AuthContext';
import { LocalizationProvider } from '@mui/x-date-pickers';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import LoginForm from './components/auth/LoginForm';
import RegisterForm from './components/auth/RegisterForm';
import TaskList from './components/tasks/TaskList';
import TaskForm from './components/tasks/TaskForm';
import PrivateRoute from './components/common/PrivateRoute';
import Layout from './components/layout/Layout';

const theme = createTheme({
  palette: {
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
  },
});

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <LocalizationProvider dateAdapter={AdapterDateFns}>
        <AuthProvider>
          <Router>
            <Routes>
              <Route path="/login" element={<LoginForm />} />
              <Route path="/register" element={<RegisterForm />} />
              <Route path="/" element={<Layout />}>
                <Route index element={<Navigate to="/tasks" replace />} />
                <Route 
                  path="/tasks" 
                  element={
                    <PrivateRoute>
                      <TaskList />
                    </PrivateRoute>
                  } 
                />
                <Route 
                  path="/tasks/new" 
                  element={
                    <PrivateRoute>
                      <TaskForm />
                    </PrivateRoute>
                  } 
                />
                <Route 
                  path="/tasks/:id/edit" 
                  element={
                    <PrivateRoute>
                      <TaskForm />
                    </PrivateRoute>
                  } 
                />
              </Route>
            </Routes>
          </Router>
        </AuthProvider>
      </LocalizationProvider>
    </ThemeProvider>
  );
}

export default App;
