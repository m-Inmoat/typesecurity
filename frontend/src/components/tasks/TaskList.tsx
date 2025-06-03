// src/components/tasks/TaskList.tsx
import React, { useState, useEffect } from 'react';
import { 
  Box, 
  Typography, 
  Paper, 
  List, 
  ListItem, 
  ListItemText, 
  Chip, 
  IconButton,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  CircularProgress
} from '@mui/material';
import { Add as AddIcon, Edit as EditIcon, Delete as DeleteIcon } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import type { Task } from '../../interfaces';
import taskService from '../../services/taskService';

const TaskList: React.FC = () => {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [taskToDelete, setTaskToDelete] = useState<Task | null>(null);
  
  const navigate = useNavigate();

  useEffect(() => {
    const fetchTasks = async () => {
      try {
        setLoading(true);
        const data = await taskService.getAllTasks();
        setTasks(data);
        setError(null);
      } catch (err) {
        console.error('Error fetching tasks:', err);
        setError('タスクの取得に失敗しました。');
      } finally {
        setLoading(false);
      }
    };

    fetchTasks();
  }, []);

  const handleAddTask = () => {
    navigate('/tasks/new');
  };

  const handleEditTask = (taskId: number) => {
    navigate(`/tasks/${taskId}/edit`);
  };

  const handleDeleteClick = (task: Task) => {
    setTaskToDelete(task);
    setDeleteDialogOpen(true);
  };

  const handleDeleteConfirm = async () => {
    if (!taskToDelete) return;
    
    try {
      await taskService.deleteTask(taskToDelete.id);
      setTasks(tasks.filter(task => task.id !== taskToDelete.id));
      setDeleteDialogOpen(false);
      setTaskToDelete(null);
    } catch (err) {
      console.error('Error deleting task:', err);
      setError('タスクの削除に失敗しました。');
    }
  };

  const handleDeleteCancel = () => {
    setDeleteDialogOpen(false);
    setTaskToDelete(null);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'TODO':
        return 'error';
      case 'IN_PROGRESS':
        return 'warning';
      case 'DONE':
        return 'success';
      default:
        return 'default';
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'HIGH':
        return 'error';
      case 'MEDIUM':
        return 'warning';
      case 'LOW':
        return 'info';
      default:
        return 'default';
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
    <Box sx={{ maxWidth: 800, mx: 'auto', mt: 4, px: 2 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1">
          タスク一覧
        </Typography>
        <Button 
          variant="contained" 
          startIcon={<AddIcon />}
          onClick={handleAddTask}
        >
          新規タスク
        </Button>
      </Box>

      {error && (
        <Paper sx={{ p: 2, mb: 3, bgcolor: 'error.light', color: 'error.contrastText' }}>
          <Typography>{error}</Typography>
        </Paper>
      )}

      {tasks.length === 0 ? (
        <Paper sx={{ p: 4, textAlign: 'center' }}>
          <Typography variant="body1">タスクがありません。新しいタスクを作成してください。</Typography>
        </Paper>
      ) : (
        <Paper elevation={2}>
          <List>
            {tasks.map((task, index) => (
              <React.Fragment key={task.id}>
                <ListItem 
                  alignItems="flex-start"
                  secondaryAction={
                    <Box>
                      <IconButton edge="end" aria-label="edit" onClick={() => handleEditTask(task.id)}>
                        <EditIcon />
                      </IconButton>
                      <IconButton edge="end" aria-label="delete" onClick={() => handleDeleteClick(task)}>
                        <DeleteIcon />
                      </IconButton>
                    </Box>
                  }
                  sx={{ py: 2 }}
                >
                  <ListItemText
                    primary={
                      <Typography variant="h6" component="div">
                        {task.title}
                      </Typography>
                    }
                    secondary={
                      <Box sx={{ mt: 1 }}>
                        <Typography variant="body2" color="text.primary" sx={{ mb: 1 }}>
                          {task.description}
                        </Typography>
                        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                          <Chip 
                            label={task.status} 
                            size="small" 
                            color={getStatusColor(task.status) as any}
                          />
                          <Chip 
                            label={`優先度: ${task.priority}`} 
                            size="small" 
                            color={getPriorityColor(task.priority) as any}
                          />
                          {task.dueDate && (
                            <Chip 
                              label={`期限: ${task.dueDate}`} 
                              size="small" 
                              variant="outlined"
                            />
                          )}
                        </Box>
                      </Box>
                    }
                  />
                </ListItem>
                {index < tasks.length - 1 && <div style={{ borderBottom: '1px solid #eee' }} />}
              </React.Fragment>
            ))}
          </List>
        </Paper>
      )}

      <Dialog
        open={deleteDialogOpen}
        onClose={handleDeleteCancel}
      >
        <DialogTitle>タスクの削除</DialogTitle>
        <DialogContent>
          <Typography>
            「{taskToDelete?.title}」を削除してもよろしいですか？この操作は元に戻せません。
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleDeleteCancel}>キャンセル</Button>
          <Button onClick={handleDeleteConfirm} color="error" autoFocus>
            削除
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default TaskList;
