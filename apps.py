from django.apps import AppConfig


class McpSqlConfig(AppConfig):
    name = "mcp_sql"
    verbose_name = "MCP SQL"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        self.validate_settings()
        self.warn_if_mfa_unconfigured()
        # Importing the module wires its @receiver-decorated handlers.
        from mcp_sql import signals

        # Lets the password-change receiver tell Django's login-time hash
        # upgrade apart from a real change (`signals._is_hash_upgrade`).
        signals.install_password_check_marker()

    @staticmethod
    def validate_settings():
        from django.conf import settings
        from mcp_sql.validation import validate_mcp_sql_settings
        from mcp_sql.validation import validate_oauth2_validator_class

        validate_mcp_sql_settings(settings.MCP_SQL)
        validate_oauth2_validator_class()

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
