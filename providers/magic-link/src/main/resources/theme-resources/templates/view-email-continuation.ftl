<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
  <#if section = "header">
    ${msg("viewEmailTitle")}
  <#elseif section = "form">
    <p id="mlc-status">${msg("magicLinkContinuationWaiting")}</p>
    <form id="mlc-poll" action="${url.loginAction}" method="post">
      <input type="hidden" name="poll" value="true"/>
    </form>
    <script>
      (function () {
        setTimeout(function () {
          document.getElementById("mlc-poll").submit();
        }, 5000);
      })();
    </script>
  </#if>
</@layout.registrationLayout>
