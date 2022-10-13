    <#import "template.ftl" as layout>
    <@layout.registrationLayout; section>
    <#if section = "title">
     title
    <#elseif section = "header">
        ${msg("loginAccountTitle")}
    <#elseif section = "form">

    <form id="webauth" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
        <div class="${properties.kcFormGroupClass!}">
            <input type="hidden" id="clientDataJSON" name="clientDataJSON"/>
            <input type="hidden" id="authenticatorData" name="authenticatorData"/>
            <input type="hidden" id="signature" name="signature"/>
            <input type="hidden" id="credentialId" name="credentialId"/>
            <input type="hidden" id="userHandle" name="userHandle"/>
            <input type="hidden" id="error" name="error"/>
        </div>
    </form>

    <#if authenticators??>
        <form id="authn_select" class="${properties.kcFormClass!}">
            <#list authenticators.authenticators as authenticator>
                <input type="hidden" name="authn_use_chk" value="${authenticator.credentialId}"/>
            </#list>
        </form>
    </#if>

    <div id="kc-form">
        <div id="kc-form-wrapper">
            <#if realm.password>
                <form id="kc-form-login" onsubmit="login.disabled = true; return true;" action="${url.loginAction}"
                      method="post">
                    <div class="${properties.kcFormGroupClass!}">
                        <label for="username"
                               class="${properties.kcLabelClass!}"><#if !realm.loginWithEmailAllowed>${msg("username")}<#elseif !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}<#else>${msg("email")}</#if></label>

                        <#if usernameEditDisabled??>
                            <input tabindex="1" id="username"
                                   aria-invalid="<#if message?has_content && message.type = 'error'>true</#if>"
                                   class="${properties.kcInputClass!}" name="username"
                                   value="${(login.username!'')}"
                                   type="text" disabled/>
                        <#else>
                            <input tabindex="1" id="username"
                                   aria-invalid="<#if messagesPerField.existsError('username')>true</#if>"
                                   class="${properties.kcInputClass!}" name="username"
                                   value="${(login.username!'')}"
                                   type="text" autofocus autocomplete="username webauthn"/>
                        </#if>

                        <#if messagesPerField.existsError('username')>
                            <span id="input-error-username" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                                ${kcSanitize(messagesPerField.get('username'))?no_esc}
                            </span>
                        </#if>
                    </div>

                    <div class="${properties.kcFormGroupClass!} ${properties.kcFormSettingClass!}">
                        <div id="kc-form-options">
                            <#if realm.rememberMe && !usernameEditDisabled??>
                                <div class="checkbox">
                                    <label>
                                        <#if login.rememberMe??>
                                            <input tabindex="3" id="rememberMe" name="rememberMe" type="checkbox"
                                                   checked> ${msg("rememberMe")}
                                        <#else>
                                            <input tabindex="3" id="rememberMe" name="rememberMe"
                                                   type="checkbox"> ${msg("rememberMe")}
                                        </#if>
                                    </label>
                                </div>
                            </#if>
                        </div>
                    </div>

                    <div id="kc-form-buttons" class="${properties.kcFormGroupClass!}">
                        <input tabindex="4"
                               class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                               name="login" id="kc-login" type="submit" value="${msg("doLogIn")}"/>
                    </div>
                </form>
            </#if>
        </div>
    </div>

    <form id="webauthn-form" class="${properties.kcFormClass!}" style="display: none;">
        <div class="login-pf-header">
            <h1>OR</h1>
        </div>
        <div class="${properties.kcFormGroupClass!}">
            <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                <input type="button" onclick="webAuthnAuthenticate(false)" value="${kcSanitize(msg("webauthn-doAuthenticate"))}"
                   class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}">
            </div>
        </div>
    </form>

    <script type="text/javascript" src="${url.resourcesCommonPath}/node_modules/jquery/dist/jquery.min.js"></script>
    <script type="text/javascript" src="${url.resourcesPath}/js/base64url.js"></script>
    <script type="text/javascript">
        window.onload = () => {
            if (!PublicKeyCredential.isConditionalMediationAvailable ||
                !PublicKeyCredential.isConditionalMediationAvailable()) {
                let form = document.getElementById("webauthn-form");
                form.style.display = "";
                return;
            }
            webAuthnAuthenticate(true);
        };

        function webAuthnAuthenticate(useConditionalUI) {
            let isUserIdentified = ${isUserIdentified};
            if (!isUserIdentified) {
                doAuthenticate([], useConditionalUI);
                return;
            }
            checkAllowCredentials(useConditionalUI);
        }

        function checkAllowCredentials(useConditionalUI) {
            let allowCredentials = [];
            let authn_use = document.forms['authn_select'].authn_use_chk;

            if (authn_use !== undefined) {
                if (authn_use.length === undefined) {
                    allowCredentials.push({
                        id: base64url.decode(authn_use.value, {loose: true}),
                        type: 'public-key',
                    });
                } else {
                    for (let i = 0; i < authn_use.length; i++) {
                        allowCredentials.push({
                            id: base64url.decode(authn_use[i].value, {loose: true}),
                            type: 'public-key',
                        });
                    }
                }
            }
            doAuthenticate(allowCredentials, useConditionalUI);
        }

        function doAuthenticate(allowCredentials, useConditionalUI) {

            // Check if WebAuthn is supported by this browser
            if (!window.PublicKeyCredential) {
                $("#error").val("${msg("webauthn-unsupported-browser-text")?no_esc}");
                $("#webauth").submit();
                return;
            }

            let challenge = "${challenge}";
            let userVerification = "${userVerification}";
            let rpId = "${rpId}";
            let publicKey = {
                rpId : rpId,
                challenge: base64url.decode(challenge, { loose: true })
            };

            if (allowCredentials.length) {
                publicKey.allowCredentials = allowCredentials;
            }

            if (userVerification !== 'not specified') publicKey.userVerification = userVerification;

            let options = {publicKey};
            if (useConditionalUI) {
                options.mediation = 'conditional';
            }

            navigator.credentials.get(options)
                .then((result) => {
                    window.result = result;

                    let clientDataJSON = result.response.clientDataJSON;
                    let authenticatorData = result.response.authenticatorData;
                    let signature = result.response.signature;

                    $("#clientDataJSON").val(base64url.encode(new Uint8Array(clientDataJSON), { pad: false }));
                    $("#authenticatorData").val(base64url.encode(new Uint8Array(authenticatorData), { pad: false }));
                    $("#signature").val(base64url.encode(new Uint8Array(signature), { pad: false }));
                    $("#credentialId").val(result.id);
                    if(result.response.userHandle) {
                        $("#userHandle").val(base64url.encode(new Uint8Array(result.response.userHandle), { pad: false }));
                    }
                    $("#webauth").submit();
                })
                .catch((err) => {
                    $("#error").val(err);
                    $("#webauth").submit();
                })
            ;
        }

    </script>
    <#elseif section = "info">

    </#if>
    </@layout.registrationLayout>