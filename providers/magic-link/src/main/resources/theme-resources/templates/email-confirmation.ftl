<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
  <#if section = "header">
    ${msg("emailConfirmationTitle")}
  <#elseif section = "form">
    <p>${msg("emailConfirmationBody")}</p>
  </#if>
</@layout.registrationLayout>
