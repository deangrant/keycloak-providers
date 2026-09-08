<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('otp'); section>
  <#if section = "header">
    ${msg("otpFormTitle")}
  <#elseif section = "form">
    <form id="kc-otp-login-form" action="${url.loginAction}" method="post">
      <div class="${properties.kcFormGroupClass!}">
        <label for="otp" class="${properties.kcLabelClass!}">${msg("otpFormLabel")}</label>
        <input id="otp" name="otp" type="text" inputmode="numeric" autocomplete="one-time-code"
               class="${properties.kcInputClass!}" autofocus/>
        <#if messagesPerField.existsError('otp')>
          <span class="${properties.kcInputErrorMessageClass!}">${kcSanitize(messagesPerField.get('otp'))?no_esc}</span>
        </#if>
      </div>
      <div class="${properties.kcFormGroupClass!}">
        <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!}" type="submit" value="${msg("doSubmit")}"/>
        <button class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!}" type="submit" name="resend" value="true">${msg("otpFormResend")}</button>
      </div>
    </form>
  </#if>
</@layout.registrationLayout>
