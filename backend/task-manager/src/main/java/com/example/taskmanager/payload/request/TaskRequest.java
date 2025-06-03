package com.example.taskmanager.payload.request;

import com.example.taskmanager.model.Task.TaskPriority;
import com.example.taskmanager.model.Task.TaskStatus;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.time.LocalDate;
import java.util.Set;

@Data
public class TaskRequest {
    @NotBlank
    private String title;
    
    private String description;
    
    @NotNull
    private TaskStatus status;
    
    @NotNull
    private TaskPriority priority;
    
    private LocalDate dueDate;
    
    private Set<Long> assigneeIds;
}
