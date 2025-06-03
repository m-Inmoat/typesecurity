package com.example.taskmanager.service;

import com.example.taskmanager.model.Task;
import com.example.taskmanager.model.User;
import com.example.taskmanager.payload.request.TaskRequest;
import com.example.taskmanager.repository.TaskRepository;
import com.example.taskmanager.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class TaskService {

    @Autowired
    private TaskRepository taskRepository;

    @Autowired
    private UserRepository userRepository;

    public List<Task> getAllTasks() {
        return taskRepository.findAll();
    }

    public Task getTaskById(Long id) {
        return taskRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Task not found with id: " + id));
    }

    public List<Task> getTasksByOwner(User owner) {
        return taskRepository.findByOwner(owner);
    }

    public List<Task> getTasksByAssignee(User assignee) {
        return taskRepository.findByAssigneesContaining(assignee);
    }

    @Transactional
    public Task createTask(TaskRequest taskRequest, String ownerUsername) {
        User owner = userRepository.findByUsername(ownerUsername)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + ownerUsername));

        Task task = new Task();
        task.setTitle(taskRequest.getTitle());
        task.setDescription(taskRequest.getDescription());
        task.setStatus(taskRequest.getStatus());
        task.setPriority(taskRequest.getPriority());
        task.setDueDate(taskRequest.getDueDate());
        task.setOwner(owner);

        // Set assignees if provided
        if (taskRequest.getAssigneeIds() != null && !taskRequest.getAssigneeIds().isEmpty()) {
            Set<User> assignees = new HashSet<>();
            for (Long userId : taskRequest.getAssigneeIds()) {
                User user = userRepository.findById(userId)
                        .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));
                assignees.add(user);
            }
            task.setAssignees(assignees);
        }

        return taskRepository.save(task);
    }

    @Transactional
    public Task updateTask(Long id, TaskRequest taskRequest) {
        Task task = taskRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Task not found with id: " + id));

        task.setTitle(taskRequest.getTitle());
        task.setDescription(taskRequest.getDescription());
        task.setStatus(taskRequest.getStatus());
        task.setPriority(taskRequest.getPriority());
        task.setDueDate(taskRequest.getDueDate());

        // Update assignees if provided
        if (taskRequest.getAssigneeIds() != null) {
            Set<User> assignees = taskRequest.getAssigneeIds().stream()
                    .map(userId -> userRepository.findById(userId)
                            .orElseThrow(() -> new RuntimeException("User not found with id: " + userId)))
                    .collect(Collectors.toSet());
            task.setAssignees(assignees);
        }

        return taskRepository.save(task);
    }

    public void deleteTask(Long id) {
        if (!taskRepository.existsById(id)) {
            throw new RuntimeException("Task not found with id: " + id);
        }
        taskRepository.deleteById(id);
    }
}
