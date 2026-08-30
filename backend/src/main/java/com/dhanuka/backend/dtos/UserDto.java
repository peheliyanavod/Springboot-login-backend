package com.dhanuka.backend.dtos;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@Data
public class UserDto {

    private Long id;
    private String email;
    private String name;
    private boolean isEmailVerified;
    private String token;
    private String refreshToken;
    private String userType;
    private String status;
    private boolean mfaRequired;
    private String mfaToken;
}
