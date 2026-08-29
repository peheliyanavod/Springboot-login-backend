package com.dhanuka.backend.repositories;

import com.dhanuka.backend.entities.SystemLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface SystemLogRepository extends JpaRepository<SystemLog, Long> {

    @Query("SELECT s FROM SystemLog s WHERE " +
           "(:userName IS NULL OR LOWER(s.user.name) LIKE LOWER(CONCAT('%', :userName, '%'))) AND " +
           "(:ipAddress IS NULL OR LOWER(s.ipAddress) LIKE LOWER(CONCAT('%', :ipAddress, '%'))) AND " +
           "(:dateFilter IS NULL OR CAST(s.dateTime as string) LIKE CONCAT('%', :dateFilter, '%')) AND " +
           "(:log IS NULL OR LOWER(s.log) LIKE LOWER(CONCAT('%', :log, '%')))")
    Page<SystemLog> searchLogs(
            @Param("userName") String userName,
            @Param("ipAddress") String ipAddress,
            @Param("dateFilter") String dateFilter,
            @Param("log") String log,
            Pageable pageable);
}
