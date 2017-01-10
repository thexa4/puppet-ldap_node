class ldap_node(
		$base,
		$admin_dn = false,
		$admin_pw = false,
		$sync_cn = 'sync',
		$sync_pw = false,
    $readonly_cn = 'readonly',
    $readonly_pw = false,
    $zone = 'dc=kamer',
	) {
	
	class { 'openldap::server':
		ldaps_ifs => ['/'],
		ssl_ca => '/etc/ssl/certs/host-ca.crt',
		ssl_cert => '/etc/ssl/certs/host.crt',
		ssl_key => '/etc/ssl/private/host.key',
	}

	if $admin_pw {
		openldap::server::database { $base:
			rootdn => $admin_dn,
			rootpw => $admin_pw,
			ensure => present,
		}
	} else {
		notify { "no rootpw set": }
		openldap::server::database { $base:
			ensure => present,
		}
	}

	package { "phpldapadmin":
		ensure => present,
		require => Openldap::Server::Database[$base],
	}

	user { "openldap":
		ensure => present,
		groups => ["ssl-cert"],
	}

	file { "/etc/phpldapadmin/config.php":
		group => www-data,
		mode => '0640',
		require => Package["phpldapadmin"],
		content => template("ldap_node/phpldapadmin-config.php.erb"),
	}

	if $syncpw {
		ldap::object { "cn=$sync_cn,$base":
			attributes => {
				"cn" => "$sync_cn",
				"description" => "Syncrepl user for mirrormode operation",
				"objectClass" => [
					"simpleSecurityObject",
					"organizationalRole",
				],
				"userPassword" => "test",
			},
			ensure => present,
			adduser => "$admin_dn",
			addpw => "$admin_pw",
		}
	}

	openldap::server::schema { "inetorgperson": ensure => present, require => [Openldap::Server::Schema["core"], Openldap::Server::Schema["cosine"]]}
	openldap::server::schema { "nis": ensure => present, require => [Openldap::Server::Schema["core"], Openldap::Server::Schema["cosine"] ]}
	openldap::server::schema { "cosine": ensure => present }
	openldap::server::schema { "core": ensure => present }
	openldap::server::schema { "dyngroup": ensure => present, require => Openldap::Server::Schema["core"]}
	openldap::server::schema { "ldapns": ensure => present, path => "/etc/ldap/schema/fusiondirectory/ldapns.schema", require => Openldap::Server::Schema["cosine"]}

	ldap::object { "${zone},$base":
		attributes => {
			"dc" => "kamer",
			"o" => "kamer.maxmaton.nl",
			"objectClass" => [
				"organization",
				"dcObject",
			],
		},
		ensure => present,
		adduser => "$admin_dn",
		addpw => "$admin_pw",
	}

	openldap::server::globalconf { "TLSVerifyClient":
		value => "try",
		ensure => present,
	}

	openldap::server::globalconf { "AuthzRegexp":
		value => "^cn=(\w+)\.(\w+)\.maxmaton\.nl\$ dc=\$1,dc=\$2,${base}",
		ensure => present,
	}

	openldap::server::access {
    "to * by self write by dn=\"${admin_dn}\" write by * read":
      ensure => absent,
      suffix   => $base;
    "to * by dn.exact=gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth manage by * break":
      ensure => absent,
      suffix   => $base;
    "Allow write to own dc":
      ensure   => present,
      what     => "dn.regex=\"(dc=[^,]+,${zone},${base})$\"",
      by       => "dn.exact,expand=\"\$1\" write by users read",
      suffix   => $base;
    "Allow creating own dc":
      ensure => present,
      what   => "dn.exact=\"${zone},${base}\"",
      by     => "dn.regex=\"^[^,]+,${zone},${base}\" write by users read",
      suffix => $base;
    "Allow rest":
      ensure => present,
      what   => "*",
      by     => "dn.exact=\"${admin_dn}\" manage by dn.exact=\"gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth\" manage by users read by * break",
      suffix => $base;
	 }
	
  if $readonly_pw {
		ldap::object { "cn=$readonly_cn,$base":
			attributes => {
				"cn" => $readonly_cn,
				"description" => "Readonly access to the whole database",
				"objectClass" => [
					"simpleSecurityObject",
					"organizationalRole",
				],
				"userPassword" => $readonly_pw,
			},
			ensure => present,
			adduser => "$admin_dn",
			addpw => "$admin_pw",
		}
    
	}
  
}
