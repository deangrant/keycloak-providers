<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
  <#if section = "header">
    ${msg("emailConfirmationErrorTitle")}
  <#elseif section = "form">
    <p>${msg("emailConfirmationErrorBody")}</p>
  </#if>
</@layout.registrationLayout>
