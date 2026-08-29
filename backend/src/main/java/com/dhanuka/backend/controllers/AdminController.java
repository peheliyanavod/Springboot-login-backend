package com.dhanuka.backend.controllers;

import com.dhanuka.backend.dtos.UserDto;
import com.dhanuka.backend.dtos.UserStatusUpdateDto;
import com.dhanuka.backend.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminController {

    private final UserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<UserDto>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @PutMapping("/users/{id}/status")
    public ResponseEntity<UserDto> updateUserStatus(
            @PathVariable Long id,
            @RequestBody UserStatusUpdateDto updateDto) {
        return ResponseEntity.ok(userService.updateUserStatus(id, updateDto.getStatus()));
    }
}
