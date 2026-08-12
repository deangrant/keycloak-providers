package me.deangrant.keycloak.magiclink.auth;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.provider.ProviderConfigProperty;

/** Parsed authenticator configuration for the magic link browser execution. */
public final class MagicLinkConfig {

  /** Config key: create a user when the submitted email does not match an existing account. */
  public static final String FORCE_CREATE = "forceCreate";

  /** Config key: add {@code UPDATE_PROFILE} when a user is created by this authenticator. */
  public static final String UPDATE_PROFILE = "updateProfile";

  /** Config key: add {@code UPDATE_PASSWORD} when a user is created by this authenticator. */
  public static final String UPDATE_PASSWORD = "updatePassword";

  /** Config key: magic-link action-token lifespan in seconds. */
  public static final String TOKEN_LIFESPAN_SECONDS = "tokenLifespanSeconds";

  public static final int DEFAULT_TOKEN_LIFESPAN_SECONDS = 15 * 60;

  /** Built-in admin-UI config properties for the magic-link authenticator. */
  public static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

  static {
    List<ProviderConfigProperty> props = new ArrayList<>();

    ProviderConfigProperty forceCreate = new ProviderConfigProperty();
    forceCreate.setName(FORCE_CREATE);
    forceCreate.setLabel("Create user if missing");
    forceCreate.setHelpText(
        "When enabled, creates a user with the submitted email as username/email if none exists.");
    forceCreate.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    forceCreate.setDefaultValue("false");
    props.add(forceCreate);

    ProviderConfigProperty updateProfile = new ProviderConfigProperty();
    updateProfile.setName(UPDATE_PROFILE);
    updateProfile.setLabel("Update profile on create");
    updateProfile.setHelpText(
        "When a user is created by this authenticator, add the UPDATE_PROFILE required action.");
    updateProfile.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    updateProfile.setDefaultValue("false");
    props.add(updateProfile);

    ProviderConfigProperty updatePassword = new ProviderConfigProperty();
    updatePassword.setName(UPDATE_PASSWORD);
    updatePassword.setLabel("Update password on create");
    updatePassword.setHelpText(
        "When a user is created by this authenticator, add the UPDATE_PASSWORD required action.");
    updatePassword.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    updatePassword.setDefaultValue("false");
    props.add(updatePassword);

    ProviderConfigProperty lifespan = new ProviderConfigProperty();
    lifespan.setName(TOKEN_LIFESPAN_SECONDS);
    lifespan.setLabel("Token lifespan (seconds)");
    lifespan.setHelpText("How long the magic link remains valid. Default is 900 (15 minutes).");
    lifespan.setType(ProviderConfigProperty.STRING_TYPE);
    lifespan.setDefaultValue(String.valueOf(DEFAULT_TOKEN_LIFESPAN_SECONDS));
    props.add(lifespan);

    CONFIG_PROPERTIES = Collections.unmodifiableList(props);
  }

  private final Map<String, String> raw;

  /**
   * Reads config from a Keycloak authenticator execution model.
   *
   * @param model authenticator config model; {@code null} yields empty defaults
   */
  public MagicLinkConfig(AuthenticatorConfigModel model) {
    this.raw =
        model == null || model.getConfig() == null ? Map.of() : Map.copyOf(model.getConfig());
  }

  /**
   * Reads config from a raw key/value map (for example customization wiring).
   *
   * @param raw config map; {@code null} yields empty defaults
   */
  public MagicLinkConfig(Map<String, String> raw) {
    this.raw = raw == null ? Map.of() : Map.copyOf(raw);
  }

  public Map<String, String> raw() {
    return raw;
  }

  public boolean isForceCreate() {
    return Boolean.parseBoolean(raw.getOrDefault(FORCE_CREATE, "false"));
  }

  public boolean isUpdateProfile() {
    return Boolean.parseBoolean(raw.getOrDefault(UPDATE_PROFILE, "false"));
  }

  public boolean isUpdatePassword() {
    return Boolean.parseBoolean(raw.getOrDefault(UPDATE_PASSWORD, "false"));
  }

  /**
   * Returns the configured token lifespan in seconds.
   *
   * <p>Missing, non-numeric, or non-positive values fall back to {@link
   * #DEFAULT_TOKEN_LIFESPAN_SECONDS}.
   */
  public OptionalInt getTokenLifespan() {
    String value = raw.get(TOKEN_LIFESPAN_SECONDS);
    if (value == null || value.isBlank()) {
      return OptionalInt.of(DEFAULT_TOKEN_LIFESPAN_SECONDS);
    }
    try {
      int parsed = Integer.parseInt(value.trim());
      return OptionalInt.of(parsed > 0 ? parsed : DEFAULT_TOKEN_LIFESPAN_SECONDS);
    } catch (NumberFormatException e) {
      return OptionalInt.of(DEFAULT_TOKEN_LIFESPAN_SECONDS);
    }
  }
}
