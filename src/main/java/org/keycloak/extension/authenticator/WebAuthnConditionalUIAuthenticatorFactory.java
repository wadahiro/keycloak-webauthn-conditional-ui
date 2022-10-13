package org.keycloak.extension.authenticator;

import com.google.auto.service.AutoService;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.browser.WebAuthnAuthenticatorFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

import static org.keycloak.provider.ProviderConfigProperty.BOOLEAN_TYPE;

@AutoService(AuthenticatorFactory.class)
public class WebAuthnConditionalUIAuthenticatorFactory extends WebAuthnAuthenticatorFactory {
    public static final String PROVIDER_ID = "webauthn-authenticator-cond-ui";

    public static final String CONFIG_USERNAME_ONLY = "username-only";
    public static final String CONFIG_CONDITIONAL_UI_ENABLED = "conditional-ui-enabled";

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> list = new ArrayList<>();
        ProviderConfigProperty rep= new ProviderConfigProperty(CONFIG_USERNAME_ONLY, "Username Only", "Username Only", BOOLEAN_TYPE, false);
        list.add(rep);
        rep = new ProviderConfigProperty(CONFIG_CONDITIONAL_UI_ENABLED, "Conditional UI", "Enable WebAuthn Conditional UI", BOOLEAN_TYPE, true);
        list.add(rep);

        return list;
    }

    @Override
    public String getReferenceCategory() {
        return WebAuthnCredentialModel.TYPE_PASSWORDLESS;
    }

    @Override
    public String getDisplayType() {
        return "WebAuthn Conditional UI Authenticator";
    }

    @Override
    public String getHelpText() {
        return "Authenticator for WebAuthn authentication with Conditional UI";
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new WebAuthnConditionalUIAuthenticator(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }
}
