package org.keycloak.extension.authenticator;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.UsernameForm;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.authentication.authenticators.browser.WebAuthnPasswordlessAuthenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.managers.AuthenticationManager;

import javax.ws.rs.core.MultivaluedMap;

import static org.keycloak.extension.authenticator.WebAuthnConditionalUIAuthenticatorFactory.CONFIG_CONDITIONAL_UI_ENABLED;
import static org.keycloak.extension.authenticator.WebAuthnConditionalUIAuthenticatorFactory.CONFIG_USERNAME_ONLY;

public class WebAuthnConditionalUIAuthenticator extends WebAuthnPasswordlessAuthenticator {

    public WebAuthnConditionalUIAuthenticator(KeycloakSession session) {
        super(session);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        super.authenticate(context);

        LoginFormsProvider form = context.form();

        form.setAttribute("usernameOnly", isUsernameOnly(context));
        form.setAttribute("conditionalUIEnabled", isConditionalUIEnabled(context));

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
            boolean usernameOnly = isUsernameOnly(context);
            if (usernameOnly) {
                boolean result = new UsernameForm().validateUser(context, formData);
                if (!result) {
                    // challenge response is set by UsernameForm
                    return;
                }
                context.attempted();
                return;
            } else {
                new UsernamePasswordForm().action(context);
                return;
            }
        }

        super.action(context);
    }

    private boolean isUsernameOnly(AuthenticationFlowContext context) {
        String usernameOnly = context.getAuthenticatorConfig().getConfig().get(CONFIG_USERNAME_ONLY);
        if (usernameOnly == null) {
            return false;
        }
        return Boolean.valueOf(usernameOnly);
    }

    private boolean isConditionalUIEnabled(AuthenticationFlowContext context) {
        String enabled = context.getAuthenticatorConfig().getConfig().get(CONFIG_CONDITIONAL_UI_ENABLED);
        if (enabled == null) {
            return false;
        }
        return Boolean.valueOf(enabled);
    }
}
