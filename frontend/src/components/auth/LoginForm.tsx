// src/components/auth/LoginForm.tsx
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { Button, TextField, Paper, Typography, Box, Alert } from '@mui/material';
import { useForm, Controller } from 'react-hook-form';

interface LoginFormInputs {
  username: string;
  password: string;
}

const LoginForm: React.FC = () => {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  
  const { control, handleSubmit, formState: { errors } } = useForm<LoginFormInputs>({
    defaultValues: {
      username: '',
      password: ''
    }
  });

  const onSubmit = async (data: LoginFormInputs) => {
    setIsLoading(true);
    setError(null);
    
    try {
      await login(data.username, data.password);
      navigate('/dashboard');
    } catch (err) {
      setError('ログインに失敗しました。ユーザー名とパスワードを確認してください。');
      console.error('Login error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Paper elevation={3} sx={{ p: 4, maxWidth: 400, mx: 'auto', mt: 8 }}>
      <Typography variant="h5" component="h1" gutterBottom align="center">
        ログイン
      </Typography>
      
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      
      <Box component="form" onSubmit={handleSubmit(onSubmit)} noValidate>
        <Controller
          name="username"
          control={control}
          rules={{ required: 'ユーザー名は必須です' }}
          render={({ field }) => (
            <TextField
              {...field}
              margin="normal"
              required
              fullWidth
              id="username"
              label="ユーザー名"
              autoComplete="username"
              autoFocus
              error={!!errors.username}
              helperText={errors.username?.message}
              disabled={isLoading}
            />
          )}
        />
        
        <Controller
          name="password"
          control={control}
          rules={{ required: 'パスワードは必須です' }}
          render={({ field }) => (
            <TextField
              {...field}
              margin="normal"
              required
              fullWidth
              id="password"
              label="パスワード"
              type="password"
              autoComplete="current-password"
              error={!!errors.password}
              helperText={errors.password?.message}
              disabled={isLoading}
            />
          )}
        />
        
        <Button
          type="submit"
          fullWidth
          variant="contained"
          sx={{ mt: 3, mb: 2 }}
          disabled={isLoading}
        >
          {isLoading ? 'ログイン中...' : 'ログイン'}
        </Button>
        
        <Button
          fullWidth
          variant="text"
          onClick={() => navigate('/register')}
          disabled={isLoading}
        >
          アカウント登録はこちら
        </Button>
      </Box>
    </Paper>
  );
};

export default LoginForm;
