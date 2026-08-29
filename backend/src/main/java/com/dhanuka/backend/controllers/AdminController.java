package com.dhanuka.backend.controllers;

import com.dhanuka.backend.dtos.UserDto;
import com.dhanuka.backend.dtos.UserStatusUpdateDto;
import com.dhanuka.backend.dtos.SystemLogDto;
import com.dhanuka.backend.services.UserService;
import com.dhanuka.backend.services.SystemLogService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletRequest;

import java.util.List;

@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminController {

    private final UserService userService;
    private final SystemLogService systemLogService;

    @GetMapping("/users")
    public ResponseEntity<List<UserDto>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @PutMapping("/users/{id}/status")
    public ResponseEntity<UserDto> updateUserStatus(
            @PathVariable Long id,
            @RequestBody UserStatusUpdateDto updateDto,
            HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        return ResponseEntity.ok(userService.updateUserStatus(id, updateDto.getStatus(), ipAddress));
    }

    @GetMapping("/logs")
    public ResponseEntity<Page<SystemLogDto>> getSystemLogs(
            @RequestParam(required = false) String userName,
            @RequestParam(required = false) String ipAddress,
            @RequestParam(required = false) String dateFilter,
            @RequestParam(required = false) String logMessage,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        
        Pageable pageable = PageRequest.of(page, size, Sort.by("dateTime").descending());
        return ResponseEntity.ok(systemLogService.getAllLogs(userName, ipAddress, dateFilter, logMessage, pageable));
    }
}
