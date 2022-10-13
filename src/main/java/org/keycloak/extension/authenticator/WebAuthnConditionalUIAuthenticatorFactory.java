package org.keycloak.extension.authenticator;

import com.google.auto.service.AutoService;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.browser.WebAuthnAuthenticatorFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.credential.WebAuthnCredentialModel;

@AutoService(AuthenticatorFactory.class)
public class WebAuthnConditionalUIAuthenticatorFactory extends WebAuthnAuthenticatorFactory {
    public static final String PROVIDER_ID = "webauthn-authenticator-cond-ui";

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
