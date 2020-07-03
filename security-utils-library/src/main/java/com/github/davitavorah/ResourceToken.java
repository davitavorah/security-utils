package com.github.davitavorah;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.keycloak.representations.idm.authorization.Permission;

import java.util.List;

@NoArgsConstructor
public final class ResourceToken {

    @Getter
    @Setter(onMethod = @__(@JsonProperty("permissions")))
    private List<Permission> permissions;

}