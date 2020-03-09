"""
CONFIGURATION:

    http_authenticator:
        accept_basic: true
        accept_digest: false
        default_to_digest: false
        trusted_auth_header:
        domain_controller: wsgidavpythodc.pytho_dc.PythoDomainController

    # WARNING: Activating the following trusted auth completely bypass all the authoritazions,
    #          which should also be resolved the by delegated proxy by analyzing paths and methods.
    # trusted_auth_header: HTTP_PYTHO_USER
    #

    # Additional options for PythoDomainController:
    #     uri           URL of Pytho Auth Service
    #     timeout       Auth timeout in seconds
    #     ticketkey     PYTHO ticket header for enhanced integration
    #     baserealm     Main realm of users
    #     superadmin    Admin can do everything on share, even outside the ufsa boundaries
    #
    # Defaults:

    pytho_dc:
        uri: http://127.0.0.1:9001
        timeout: 15
        ticketkey: doob-tkt
        baserealm: /ufsa
        superadmin: false

"""