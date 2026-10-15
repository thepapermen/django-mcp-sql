from django.apps import AppConfig


class McpSqlConfig(AppConfig):
    name = "mcp_sql"
    verbose_name = "MCP SQL"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        self.validate_settings()
        self.check_sql_dialect()
        self.warn_if_mfa_unconfigured()
        # Importing the modules wires their @receiver-decorated handlers
        # and @register-ed system checks.
        from mcp_sql import checks  # noqa: F401
        from mcp_sql import signals

        # Lets the password-change receiver tell Django's login-time hash
        # upgrade apart from a real change (`signals._is_hash_upgrade`).
        signals.install_password_check_marker()

    @staticmethod
    def validate_settings():
        """Validate whatever the consumer declared — including nothing.

        Every `MCP_SQL` key carries an in-package default, so an absent
        setting is a valid (if useless: no readable tables, no MFA checker)
        configuration rather than a boot error. `validate_mcp_sql_settings`
        merges over the defaults before checking, so the shipped defaults are
        re-validated on every boot too.
        """
        from django.conf import settings
        from mcp_sql.validation import validate_mcp_sql_settings
        from mcp_sql.validation import validate_oauth2_validator_class

        validate_mcp_sql_settings(getattr(settings, "MCP_SQL", {}))
        validate_oauth2_validator_class()

    @staticmethod
    def check_sql_dialect():
        """Refuse to start where the parser's dialect cannot be built
        (`parser.dialect_problem`: sqlglot's compiled build), instead of
        refusing every query as `parse_error`."""
        from django.core.exceptions import ImproperlyConfigured
        from mcp_sql.parser import dialect_problem

        problem = dialect_problem()
        if problem is not None:
            msg = (
                f"mcp_sql cannot build its SQL dialect ({problem}). sqlglot's "
                "compiled build (the `sqlglot[c]` extra, package `sqlglotc`) "
                "cannot be subclassed, so every query would be refused as "
                "parse_error. Uninstall it (`pip uninstall sqlglotc`) and "
                "depend on plain `sqlglot`."
            )
            raise ImproperlyConfigured(msg)

    @staticmethod
    def warn_if_mfa_unconfigured():
        """Loudly flag the fail-closed default MFA checker at startup.

        The in-package default (`deny_unconfigured_mfa`) denies every
        MFA-gated decision, so a consumer who never set
        `MCP_SQL["MFA_CHECKER"]` would find the whole MCP surface
        inaccessible. That's the safe failure (fail-closed), but a silent
        one is mystifying — emit one WARNING per process so the cause is
        obvious in logs.
        """
        import logging

        from mcp_sql.conf import deny_unconfigured_mfa
        from mcp_sql.conf import mcp_sql_settings

        if mcp_sql_settings.MFA_CHECKER is deny_unconfigured_mfa:
            logging.getLogger("mcp_sql").warning(
                "MCP SQL is using the fail-closed default MFA checker "
                "(deny_unconfigured_mfa): every MFA-gated decision will be "
                "DENIED until MCP_SQL['MFA_CHECKER'] is set to a real check "
                "(django-allauth projects use 'allauth.mfa.utils.is_mfa_enabled')."
            )
