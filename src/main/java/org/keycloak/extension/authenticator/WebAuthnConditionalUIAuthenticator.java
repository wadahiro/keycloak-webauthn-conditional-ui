package org.keycloak.extension.authenticator;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.UsernameForm;
import org.keycloak.authentication.authenticators.browser.WebAuthnPasswordlessAuthenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.managers.AuthenticationManager;

import javax.ws.rs.core.MultivaluedMap;

public class WebAuthnConditionalUIAuthenticator extends WebAuthnPasswordlessAuthenticator {

    public WebAuthnConditionalUIAuthenticator(KeycloakSession session) {
        super(session);
    }

    public void authenticate(AuthenticationFlowContext context) {
        super.authenticate(context);

        LoginFormsProvider form = context.form();
        context.challenge(form.createForm("webauthn-conditional-authenticate.ftl"));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }

        String username = formData.getFirst(AuthenticationManager.FORM_USERNAME);
        if (username != null) {
            boolean result = new UsernameForm().validateUser(context, formData);
            if (!result) {
                // challenge response is set by UsernameForm
                return;
            }

            context.attempted();
            return;
        }

        super.action(context);
    }
}
