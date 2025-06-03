package com.example.taskmanager.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.taskmanager.model.Task;
import com.example.taskmanager.model.User;
import com.example.taskmanager.payload.request.TaskRequest;
import com.example.taskmanager.payload.response.MessageResponse;
import com.example.taskmanager.repository.UserRepository;
import com.example.taskmanager.security.services.UserDetailsImpl;
import com.example.taskmanager.service.TaskService;

import jakarta.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/tasks")
public class TaskController {

    @Autowired
    private TaskService taskService;

    @Autowired
    private UserRepository userRepository;

    @GetMapping
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<List<Task>> getAllTasks() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        
        // Admins can see all tasks, users can only see their own or assigned tasks
        if (authentication.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
            return ResponseEntity.ok(taskService.getAllTasks());
        } else {
            User user = userRepository.findById(userDetails.getId())
                    .orElseThrow(() -> new RuntimeException("User not found"));
            List<Task> ownedTasks = taskService.getTasksByOwner(user);
            List<Task> assignedTasks = taskService.getTasksByAssignee(user);
            
            // Combine and remove duplicates
            ownedTasks.addAll(assignedTasks);
            return ResponseEntity.ok(ownedTasks.stream().distinct().toList());
        }
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<?> getTaskById(@PathVariable Long id) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        
        Task task = taskService.getTaskById(id);
        
        // Check if user has access to this task
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        boolean isOwner = task.getOwner().getId().equals(userDetails.getId());
        boolean isAssignee = task.getAssignees().stream()
                .anyMatch(user -> user.getId().equals(userDetails.getId()));
        
        if (isAdmin || isOwner || isAssignee) {
            return ResponseEntity.ok(task);
        } else {
            return ResponseEntity.status(403).body(new MessageResponse("Access denied"));
        }
    }

    @PostMapping
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<?> createTask(@Valid @RequestBody TaskRequest taskRequest) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        
        Task task = taskService.createTask(taskRequest, userDetails.getUsername());
        return ResponseEntity.ok(task);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<?> updateTask(@PathVariable Long id, @Valid @RequestBody TaskRequest taskRequest) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        
        Task task = taskService.getTaskById(id);
        
        // Check if user has permission to update this task
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        boolean isOwner = task.getOwner().getId().equals(userDetails.getId());
        
        if (isAdmin || isOwner) {
            Task updatedTask = taskService.updateTask(id, taskRequest);
            return ResponseEntity.ok(updatedTask);
        } else {
            return ResponseEntity.status(403).body(new MessageResponse("Access denied"));
        }
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<?> deleteTask(@PathVariable Long id) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        
        Task task = taskService.getTaskById(id);
        
        // Check if user has permission to delete this task
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        boolean isOwner = task.getOwner().getId().equals(userDetails.getId());
        
        if (isAdmin || isOwner) {
            taskService.deleteTask(id);
            return ResponseEntity.ok(new MessageResponse("Task deleted successfully"));
        } else {
            return ResponseEntity.status(403).body(new MessageResponse("Access denied"));
        }
    }

    @GetMapping("/user/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<Task>> getTasksByUserId(@PathVariable Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));
        
        List<Task> tasks = taskService.getTasksByOwner(user);
        return ResponseEntity.ok(tasks);
    }
}
