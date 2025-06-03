// src/components/tasks/TaskForm.tsx
import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { 
  Box, 
  Typography, 
  Paper, 
  TextField, 
  Button, 
  FormControl, 
  InputLabel, 
  Select, 
  MenuItem, 
  FormHelperText,
  Alert,
  CircularProgress
} from '@mui/material';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import { useForm, Controller } from 'react-hook-form';
import type { Task, TaskRequest } from '../../interfaces';
import taskService from '../../services/taskService';

interface TaskFormInputs {
  title: string;
  description: string;
  status: 'TODO' | 'IN_PROGRESS' | 'DONE';
  priority: 'LOW' | 'MEDIUM' | 'HIGH';
  dueDate: Date | null;
}

const TaskForm: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const isEditMode = !!id;
  const navigate = useNavigate();
  
  const [loading, setLoading] = useState(isEditMode);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  
  const { control, handleSubmit, reset, formState: { errors } } = useForm<TaskFormInputs>({
    defaultValues: {
      title: '',
      description: '',
      status: 'TODO',
      priority: 'MEDIUM',
      dueDate: null
    }
  });

  useEffect(() => {
    const fetchTask = async () => {
      if (!isEditMode) return;
      
      try {
        setLoading(true);
        const task = await taskService.getTaskById(Number(id));
        
        reset({
          title: task.title,
          description: task.description,
          status: task.status,
          priority: task.priority,
          dueDate: task.dueDate ? new Date(task.dueDate) : null
        });
        
        setError(null);
      } catch (err) {
        console.error('Error fetching task:', err);
        setError('タスクの取得に失敗しました。');
      } finally {
        setLoading(false);
      }
    };

    fetchTask();
  }, [id, isEditMode, reset]);

  const onSubmit = async (data: TaskFormInputs) => {
    setSubmitting(true);
    setError(null);
    
    try {
      const taskData: TaskRequest = {
        title: data.title,
        description: data.description,
        status: data.status,
        priority: data.priority,
        dueDate: data.dueDate ? data.dueDate.toISOString().split('T')[0] : undefined,
        assigneeIds: []
      };
      
      if (isEditMode) {
        await taskService.updateTask(Number(id), taskData);
      } else {
        await taskService.createTask(taskData);
      }
      
      navigate('/tasks');
    } catch (err) {
      console.error('Error saving task:', err);
      setError(`タスクの${isEditMode ? '更新' : '作成'}に失敗しました。`);
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="200px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ maxWidth: 600, mx: 'auto', mt: 4, px: 2 }}>
      <Typography variant="h4" component="h1" gutterBottom>
        {isEditMode ? 'タスクの編集' : '新規タスク作成'}
      </Typography>
      
      {error && <Alert severity="error" sx={{ mb: 3 }}>{error}</Alert>}
      
      <Paper elevation={2} sx={{ p: 3 }}>
        <Box component="form" onSubmit={handleSubmit(onSubmit)} noValidate>
          <Controller
            name="title"
            control={control}
            rules={{ required: 'タイトルは必須です' }}
            render={({ field }) => (
              <TextField
                {...field}
                margin="normal"
                required
                fullWidth
                id="title"
                label="タイトル"
                autoFocus
                error={!!errors.title}
                helperText={errors.title?.message}
                disabled={submitting}
              />
            )}
          />
          
          <Controller
            name="description"
            control={control}
            render={({ field }) => (
              <TextField
                {...field}
                margin="normal"
                fullWidth
                id="description"
                label="説明"
                multiline
                rows={4}
                error={!!errors.description}
                helperText={errors.description?.message}
                disabled={submitting}
              />
            )}
          />
          
          <Box sx={{ display: 'flex', gap: 2, mt: 2 }}>
            <Controller
              name="status"
              control={control}
              rules={{ required: 'ステータスは必須です' }}
              render={({ field }) => (
                <FormControl fullWidth error={!!errors.status} disabled={submitting}>
                  <InputLabel id="status-label">ステータス</InputLabel>
                  <Select
                    {...field}
                    labelId="status-label"
                    id="status"
                    label="ステータス"
                  >
                    <MenuItem value="TODO">TODO</MenuItem>
                    <MenuItem value="IN_PROGRESS">IN_PROGRESS</MenuItem>
                    <MenuItem value="DONE">DONE</MenuItem>
                  </Select>
                  {errors.status && <FormHelperText>{errors.status.message}</FormHelperText>}
                </FormControl>
              )}
            />
            
            <Controller
              name="priority"
              control={control}
              rules={{ required: '優先度は必須です' }}
              render={({ field }) => (
                <FormControl fullWidth error={!!errors.priority} disabled={submitting}>
                  <InputLabel id="priority-label">優先度</InputLabel>
                  <Select
                    {...field}
                    labelId="priority-label"
                    id="priority"
                    label="優先度"
                  >
                    <MenuItem value="LOW">LOW</MenuItem>
                    <MenuItem value="MEDIUM">MEDIUM</MenuItem>
                    <MenuItem value="HIGH">HIGH</MenuItem>
                  </Select>
                  {errors.priority && <FormHelperText>{errors.priority.message}</FormHelperText>}
                </FormControl>
              )}
            />
          </Box>
          
          <Box sx={{ mt: 2 }}>
            <LocalizationProvider dateAdapter={AdapterDateFns}>
              <Controller
                name="dueDate"
                control={control}
                render={({ field }) => (
                  <DatePicker
                    label="期限日"
                    value={field.value}
                    onChange={(newValue) => field.onChange(newValue)}
                    disabled={submitting}
                    slotProps={{
                      textField: {
                        fullWidth: true,
                        margin: 'normal'
                      }
                    }}
                  />
                )}
              />
            </LocalizationProvider>
          </Box>
          
          <Box sx={{ mt: 3, display: 'flex', gap: 2 }}>
            <Button
              type="submit"
              variant="contained"
              disabled={submitting}
              sx={{ flex: 1 }}
            >
              {submitting ? '保存中...' : (isEditMode ? '更新' : '作成')}
            </Button>
            
            <Button
              variant="outlined"
              onClick={() => navigate('/tasks')}
              disabled={submitting}
              sx={{ flex: 1 }}
            >
              キャンセル
            </Button>
          </Box>
        </Box>
      </Paper>
    </Box>
  );
};

export default TaskForm;
