package com.github.davitavorah.autoconfigure;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "security.utils")
public class SecurityProperties {

    private String password = "123456";
    private String login = "superadmin";

}
