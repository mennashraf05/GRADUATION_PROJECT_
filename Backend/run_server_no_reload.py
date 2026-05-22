import app as sentinel_app


def main() -> None:
    sentinel_app.init_db()
    sentinel_app.import_leaked_csv()
    with sentinel_app.app.app_context():
        sentinel_app.db.create_all()
        sentinel_app._ensure_auth_security_schema_initialized()
        sentinel_app._ensure_notification_schema_initialized()
        sentinel_app._ensure_pcap_alert_schema_initialized()
        sentinel_app.ensure_gamification_schema_initialized()

    sentinel_app.app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
