@{
    # =====================================================================
    # Mapping ZONE (datacenter) -> parametres Vault / PVWA / CCP.
    # Les 2 datacenters ont des flux fermes entre eux : on selectionne la
    # zone au lancement (-Zone) puis on confirme interactivement.
    #
    # Aucun secret ici. Le mot de passe du compte admin/install Vault est
    # recupere via le CCP au runtime (par AppID/Safe/Object ci-dessous).
    #
    # ClientCertThumbprint :
    #   - renseigne -> appel CCP en TLS mutuel (endpoint "Require client cert")
    #   - vide      -> appel CCP par IP/OS autorisee (endpoint legacy)
    # =====================================================================

    DC1 = @{
        Name                 = 'DC1'
        PvwaUrl              = 'https://<PVWA-DC1>'        # TODO (deploiement)
        PvwaAuthMethod       = 'CyberArk'                  # CyberArk | LDAP | RADIUS
        CcpUrl               = 'https://<CCP-DC1>'         # TODO (deploiement)
        ClientCertThumbprint = ''                          # TODO : thumbprint si endpoint cert
        AppId                = '<APPID-DC1>'               # AppID CCP pour le compte admin Vault
        Safe                 = '<SAFE-ADMIN-DC1>'          # Safe du compte admin/install
        ObjectName           = '<OBJECT-ADMIN-DC1>'        # Nom d'objet du compte admin/install
    }

    DC2 = @{
        Name                 = 'DC2'
        PvwaUrl              = 'https://<PVWA-DC2>'        # TODO (deploiement)
        PvwaAuthMethod       = 'CyberArk'
        CcpUrl               = 'https://<CCP-DC2>'         # TODO (deploiement)
        ClientCertThumbprint = ''                          # TODO : thumbprint si endpoint cert
        AppId                = '<APPID-DC2>'
        Safe                 = '<SAFE-ADMIN-DC2>'
        ObjectName           = '<OBJECT-ADMIN-DC2>'
    }
}
