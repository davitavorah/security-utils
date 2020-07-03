package com.github.davitavorah.autoconfigure;

import io.vavr.Tuple2;
import io.vavr.Value;
import io.vavr.collection.List;
import lombok.RequiredArgsConstructor;
import org.apache.http.impl.client.HttpClientBuilder;
import org.keycloak.AuthorizationContext;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springboot.KeycloakSpringBootProperties;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.token.TokenManager;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.annotation.RequestScope;

import java.util.stream.Collectors;

import static io.vavr.collection.HashMap.ofAll;

@Configuration
@RequiredArgsConstructor
@ConditionalOnProperty("keycloak.enabled")
@EnableConfigurationProperties(SecurityProperties.class)
public class SecurityUtilsAutoConfiguration {

    private static final String DEFAULT_ROLE_ACCOUNT = "account";
    private static final String DEFAULT_ROLE_REALM_MANAGEMENT = "realm-management";

    @Bean
    @RequestScope
    protected KeycloakPrincipal keycloakPrincipal() {
        return (KeycloakPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

    @Bean
    @RequestScope
    protected KeycloakSecurityContext keycloakSecurityContext(KeycloakPrincipal keycloakPrincipal) {
        return keycloakPrincipal.getKeycloakSecurityContext();
    }

    @Bean
    @RequestScope
    protected AuthorizationContext authorizationContext(KeycloakSecurityContext keycloakSecurityContext) {
        return keycloakSecurityContext.getAuthorizationContext();
    }

    @Bean
    @RequestScope
    protected AccessToken accessToken(KeycloakSecurityContext keycloakSecurityContext) {
        return keycloakSecurityContext.getToken();
    }

    @Bean
    @Scope(value = ConfigurableBeanFactory.SCOPE_SINGLETON)
    public Keycloak getKeycloakInstance(KeycloakSpringBootProperties kcProperties, SecurityProperties scProperties, KeycloakSecurityContext accessToken) {
        return Keycloak.getInstance(kcProperties.getAuthServerUrl(),
                kcProperties.getRealm(),
                scProperties.getLogin(),
                scProperties.getPassword(),
                kcProperties.getResource(),
                kcProperties.getCredentials().get(CredentialRepresentation.SECRET).toString());
    }

    @Bean
    @Scope(value = ConfigurableBeanFactory.SCOPE_SINGLETON)
    public AuthzClient authzClient(KeycloakSpringBootProperties kcProperties) {
        org.keycloak.authorization.client.Configuration configuration = new org.keycloak.authorization.client.Configuration(
                kcProperties.getAuthServerUrl(), kcProperties.getRealm(),
                kcProperties.getResource(), kcProperties.getCredentials(), HttpClientBuilder.create().build());
        return AuthzClient.create(configuration);
    }

    @Bean
    @Scope(value = ConfigurableBeanFactory.SCOPE_SINGLETON)
    public RealmResource getRealmResource(KeycloakSpringBootProperties kcProperties, Keycloak keycloak) {
        return keycloak.realm(kcProperties.getRealm());
    }

    @Bean
    @Scope(value = ConfigurableBeanFactory.SCOPE_SINGLETON)
    public TokenManager getToken(Keycloak keycloak) {
        return keycloak.tokenManager();
    }

    @Bean
    @RequestScope
    public UserRepresentation getLoggedUser(KeycloakSecurityContext keycloakSecurityContext, RealmResource realmResource) {
        final var userId = keycloakSecurityContext.getToken().getSubject();
        final var loggedUser = realmResource.users().get(userId).toRepresentation();
        var userRoles = ofAll(keycloakSecurityContext.getToken().getResourceAccess())
                .filter(this::doesNotHaveDefaultRoles)
                .mapValues(AccessToken.Access::getRoles)
                .mapValues(List::ofAll)
                .mapValues(Value::toJavaList)
                .collect(Collectors.toMap(Tuple2::_1, Tuple2::_2));
        loggedUser.setClientRoles(userRoles);
        return loggedUser;
    }

    private boolean doesNotHaveDefaultRoles(Tuple2<String, AccessToken.Access> access) {
        return !DEFAULT_ROLE_REALM_MANAGEMENT.equals(access._1) && !DEFAULT_ROLE_ACCOUNT.equals(access._1);
    }

}
