<#-- Magic link email (HTML) -->
<html>
<body>
${kcSanitize(msg("magicLinkSubject", realmName, clientName))?no_esc}
<p>Click the link below to sign in to <strong>${realmName}</strong>${clientName?has_content?then(" (" + clientName + ")", "")}:</p>
<p><a href="${magicLink}">${magicLink}</a></p>
<p>If you did not request this email, you can ignore it.</p>
</body>
</html>
