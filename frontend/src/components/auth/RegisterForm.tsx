// src/components/auth/RegisterForm.tsx
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { Button, TextField, Paper, Typography, Box, Alert } from '@mui/material';
import { useForm, Controller } from 'react-hook-form';

interface RegisterFormInputs {
  username: string;
  email: string;
  password: string;
  confirmPassword: string;
}

const RegisterForm: React.FC = () => {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  
  const { control, handleSubmit, formState: { errors }, watch } = useForm<RegisterFormInputs>({
    defaultValues: {
      username: '',
      email: '',
      password: '',
      confirmPassword: ''
    }
  });

  const password = watch('password');

  const onSubmit = async (data: RegisterFormInputs) => {
    setIsLoading(true);
    setError(null);
    
    try {
      await register(data.username, data.email, data.password);
      navigate('/login', { state: { message: '登録が完了しました。ログインしてください。' } });
    } catch (err) {
      setError('登録に失敗しました。ユーザー名またはメールアドレスが既に使用されている可能性があります。');
      console.error('Registration error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Paper elevation={3} sx={{ p: 4, maxWidth: 400, mx: 'auto', mt: 8 }}>
      <Typography variant="h5" component="h1" gutterBottom align="center">
        アカウント登録
      </Typography>
      
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      
      <Box component="form" onSubmit={handleSubmit(onSubmit)} noValidate>
        <Controller
          name="username"
          control={control}
          rules={{ 
            required: 'ユーザー名は必須です',
            minLength: { value: 3, message: 'ユーザー名は3文字以上必要です' },
            maxLength: { value: 20, message: 'ユーザー名は20文字以下にしてください' }
          }}
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
          name="email"
          control={control}
          rules={{ 
            required: 'メールアドレスは必須です',
            pattern: { value: /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i, message: '有効なメールアドレスを入力してください' }
          }}
          render={({ field }) => (
            <TextField
              {...field}
              margin="normal"
              required
              fullWidth
              id="email"
              label="メールアドレス"
              autoComplete="email"
              error={!!errors.email}
              helperText={errors.email?.message}
              disabled={isLoading}
            />
          )}
        />
        
        <Controller
          name="password"
          control={control}
          rules={{ 
            required: 'パスワードは必須です',
            minLength: { value: 6, message: 'パスワードは6文字以上必要です' },
            maxLength: { value: 40, message: 'パスワードは40文字以下にしてください' }
          }}
          render={({ field }) => (
            <TextField
              {...field}
              margin="normal"
              required
              fullWidth
              id="password"
              label="パスワード"
              type="password"
              autoComplete="new-password"
              error={!!errors.password}
              helperText={errors.password?.message}
              disabled={isLoading}
            />
          )}
        />
        
        <Controller
          name="confirmPassword"
          control={control}
          rules={{ 
            required: 'パスワード（確認）は必須です',
            validate: value => value === password || 'パスワードが一致しません'
          }}
          render={({ field }) => (
            <TextField
              {...field}
              margin="normal"
              required
              fullWidth
              id="confirmPassword"
              label="パスワード（確認）"
              type="password"
              autoComplete="new-password"
              error={!!errors.confirmPassword}
              helperText={errors.confirmPassword?.message}
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
          {isLoading ? '登録中...' : '登録'}
        </Button>
        
        <Button
          fullWidth
          variant="text"
          onClick={() => navigate('/login')}
          disabled={isLoading}
        >
          既にアカウントをお持ちの方はこちら
        </Button>
      </Box>
    </Paper>
  );
};

export default RegisterForm;
