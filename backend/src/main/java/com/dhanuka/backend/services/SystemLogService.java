package com.dhanuka.backend.services;

import com.dhanuka.backend.entities.SystemLog;
import com.dhanuka.backend.entities.User;
import com.dhanuka.backend.dtos.SystemLogDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import com.dhanuka.backend.repositories.SystemLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class SystemLogService {

    private final SystemLogRepository systemLogRepository;

    @Transactional
    public void saveLog(User user, String ipAddress, String message) {
        if (user == null) {
            return; // Can't log without a user
        }
        
        SystemLog log = SystemLog.builder()
                .user(user)
                .ipAddress(ipAddress != null ? ipAddress : "Unknown")
                .log(message)
                .build();
                
        systemLogRepository.save(log);
    }

    public Page<SystemLogDto> getAllLogs(String userName, String ipAddress, String dateFilter, String logMessage, Pageable pageable) {
        return systemLogRepository.searchLogs(userName, ipAddress, dateFilter, logMessage, pageable)
                .map(log -> SystemLogDto.builder()
                        .id(log.getId())
                        .userName(log.getUser().getName())
                        .ipAddress(log.getIpAddress())
                        .dateTime(log.getDateTime())
                        .log(log.getLog())
                        .build());
    }
}
