<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
  <#if section = "header">
    ${msg("viewEmailTitle")}
  <#elseif section = "form">
    <p>${msg("viewEmailBody")}</p>
  </#if>
</@layout.registrationLayout>
