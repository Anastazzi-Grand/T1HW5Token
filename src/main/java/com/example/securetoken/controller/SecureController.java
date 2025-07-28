package com.example.securetoken.controller;

import com.example.securetoken.dto.UserDto;
import com.example.securetoken.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
@Tag(name = "Пользователь", description = "API для работы с данными пользователя")
public class SecureController {

    private final UserService userService;

    @GetMapping("/user")
    @Operation(
            summary = "Получить данные текущего пользователя",
            security = @SecurityRequirement(name = "bearerAuth"),
            responses = {
                    @ApiResponse(responseCode = "200", description = "Данные пользователя",
                            content = @Content(schema = @Schema(implementation = UserDto.class)))
            }
    )
    public ResponseEntity<UserDto> getCurrentUser(@AuthenticationPrincipal UserDetails userDetails) {
        UserDto user = userService.findByUsername(userDetails.getUsername());
        return ResponseEntity.ok(user);
    }

    @GetMapping("/admin")
    @Operation(
            summary = "Только для администраторов",
            security = @SecurityRequirement(name = "bearerAuth"),
            responses = {
                    @ApiResponse(responseCode = "200", description = "Доступ разрешён"),
                    @ApiResponse(responseCode = "403", description = "Нет прав")
            }
    )
    public ResponseEntity<String> adminOnly() {
        return ResponseEntity.ok("Только для администраторов!");
    }
}