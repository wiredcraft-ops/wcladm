package templates

import (
	"text/template"

	"github.com/lithammer/dedent"
)

var (
	HarborConfigTempl = template.Must(template.New("harbor").Parse(dedent.Dedent(`
		## Configuration file of Harbor

		#This attribute is for migrator to detect the version of the .cfg file, DO NOT MODIFY!
		_version = 1.5.0
		#The IP address or hostname to access admin UI and registry service.
		#DO NOT use localhost or 127.0.0.1, because Harbor needs to be accessed by external clients.
		hostname = {{ .HostName }}

		#The protocol for accessing the UI and token/notification service, by default it is http.
		#It can be set to https if ssl is enabled on nginx.
		ui_url_protocol = {{ .Scheme }}

		#Maximum number of job workers in job service
		max_job_workers = 50

		#Determine whether or not to generate certificate for the registry's token.
		#If the value is on, the prepare script creates new root cert and private key
		#for generating token to access the registry. If the value is off the default key/cert will be used.
		#This flag also controls the creation of the notary signer's cert.
		customize_crt = on

		#The path of cert and key files for nginx, they are applied only the protocol is set to https
		ssl_cert = {{ .SSLCert }}
		ssl_cert_key = {{ .SSLCertKey }}

		#The path of secretkey storage
		secretkey_path = /data

		#Admiral's url, comment this attribute, or set its value to NA when Harbor is standalone
		admiral_url = NA

		#Log files are rotated log_rotate_count times before being removed. If count is 0, old versions are removed rather than rotated.
		log_rotate_count = 50
		#Log files are rotated only if they grow bigger than log_rotate_size bytes. If size is followed by k, the size is assumed to be in kilobytes.
		#If the M is used, the size is in megabytes, and if G is used, the size is in gigabytes. So size 100, size 100k, size 100M and size 100G
		#are all valid.
		log_rotate_size = 200M

		#Config http proxy for Clair, e.g. http://my.proxy.com:3128
		#Clair doesn't need to connect to harbor ui container via http proxy.
		http_proxy =
		https_proxy =
		no_proxy = 127.0.0.1,localhost,ui

		#NOTES: The properties between BEGIN INITIAL PROPERTIES and END INITIAL PROPERTIES
		#only take effect in the first boot, the subsequent changes of these properties
		#should be performed on web ui

		#************************BEGIN INITIAL PROPERTIES************************

		#Email account settings for sending out password resetting emails.

		#Email server uses the given username and password to authenticate on TLS connections to host and act as identity.
		#Identity left blank to act as username.
		email_identity =

		email_server = smtp.mydomain.com
		email_server_port = 25
		email_username = sample_admin@mydomain.com
		email_password = abc
		email_from = admin <sample_admin@mydomain.com>
		email_ssl = false
		email_insecure = false

		##The initial password of Harbor admin, only works for the first time when Harbor starts.
		#It has no effect after the first launch of Harbor.
		#Change the admin password from UI after launching Harbor.
		harbor_admin_password = {{ .AdminPassword }}

		##By default the auth mode is db_auth, i.e. the credentials are stored in a local database.
		#Set it to ldap_auth if you want to verify a user's credentials against an LDAP server.
		auth_mode = db_auth

		#The url for an ldap endpoint.
		ldap_url = ldaps://ldap.mydomain.com

		#A user's DN who has the permission to search the LDAP/AD server.
		#If your LDAP/AD server does not support anonymous search, you should configure this DN and ldap_search_pwd.
		#ldap_searchdn = uid=searchuser,ou=people,dc=mydomain,dc=com

		#the password of the ldap_searchdn
		#ldap_search_pwd = password

		#The base DN from which to look up a user in LDAP/AD
		ldap_basedn = ou=people,dc=mydomain,dc=com

		#Search filter for LDAP/AD, make sure the syntax of the filter is correct.
		#ldap_filter = (objectClass=person)

		# The attribute used in a search to match a user, it could be uid, cn, email, sAMAccountName or other attributes depending on your LDAP/AD
		ldap_uid = uid

		#the scope to search for users, 0-LDAP_SCOPE_BASE, 1-LDAP_SCOPE_ONELEVEL, 2-LDAP_SCOPE_SUBTREE
		ldap_scope = 2

		#Timeout (in seconds)  when connecting to an LDAP Server. The default value (and most reasonable) is 5 seconds.
		ldap_timeout = 5

		#Verify certificate from LDAP server
		ldap_verify_cert = true

		#The base dn from which to lookup a group in LDAP/AD
		ldap_group_basedn = ou=group,dc=mydomain,dc=com

		#filter to search LDAP/AD group
		ldap_group_filter = objectclass=group

		#The attribute used to name a LDAP/AD group, it could be cn, name
		ldap_group_gid = cn

		#The scope to search for ldap groups. 0-LDAP_SCOPE_BASE, 1-LDAP_SCOPE_ONELEVEL, 2-LDAP_SCOPE_SUBTREE
		ldap_group_scope = 2

		#Turn on or off the self-registration feature
		self_registration = on

		#The expiration time (in minute) of token created by token service, default is 30 minutes
		token_expiration = 30

		#The flag to control what users have permission to create projects
		#The default value "everyone" allows everyone to creates a project.
		#Set to "adminonly" so that only admin user can create project.
		project_creation_restriction = everyone

		#************************END INITIAL PROPERTIES************************

		#######Harbor DB configuration section#######

		#The address of the Harbor database. Only need to change when using external db.
		db_host = mysql

		#The password for the root user of Harbor DB. Change this before any production use.
		db_password = {{ .DBPassword }}

		#The port of Harbor database host
		db_port = 3306

		#The user name of Harbor database
		db_user = root

		##### End of Harbor DB configuration#######

		#The redis server address. Only needed in HA installation.
		#address:port[,weight,password,db_index]
		redis_url = redis:6379

		##########Clair DB configuration############

		#Clair DB host address. Only change it when using an exteral DB.
		clair_db_host = postgres

		#The password of the Clair's postgres database. Only effective when Harbor is deployed with Clair.
		#Please update it before deployment. Subsequent update will cause Clair's API server and Harbor unable to access Clair's database.
		clair_db_password = password

		#Clair DB connect port
		clair_db_port = 5432

		#Clair DB username
		clair_db_username = postgres

		#Clair default database
		clair_db = postgres

		##########End of Clair DB configuration############

		#The following attributes only need to be set when auth mode is uaa_auth
		uaa_endpoint = uaa.mydomain.org
		uaa_clientid = id
		uaa_clientsecret = secret
		uaa_verify_cert = true
		uaa_ca_cert = /path/to/ca.pem


		### Docker Registry setting ###
		#registry_storage_provider can be: filesystem, s3, gcs, azure, etc.
		registry_storage_provider_name = filesystem
		#registry_storage_provider_config is a comma separated "key: value" pairs, e.g. "key1: value, key2: value2".
		#Refer to https://docs.docker.com/registry/configuration/#storage for all available configuration.
		registry_storage_provider_config =

	`)))

	HarborPrepareTempl = template.Must(template.New("harbor").Parse(dedent.Dedent(`
		#!/usr/bin/python
		# -*- coding: utf-8 -*-
		from __future__ import print_function, unicode_literals  # We require Python 2.6 or later
		from string import Template
		import random
		import string
		import os
		import sys
		import argparse
		import subprocess
		import shutil
		from io import open

		if sys.version_info[:3][0] == 2:
			import ConfigParser as ConfigParser
			import StringIO as StringIO

		if sys.version_info[:3][0] == 3:
			import configparser as ConfigParser
			import io as StringIO


		def validate(conf, args):
			if args.ha_mode:
				db_host = rcp.get("configuration", "db_host")
				if db_host == "mysql":
					raise Exception(
						"Error: In HA mode, db_host in harbor.cfg needs to point to an external DB address."
					)
				registry_storage_provider_name = rcp.get(
					"configuration", "registry_storage_provider_name").strip()
				if registry_storage_provider_name == "filesystem" and not args.yes:
					msg = 'Is the Harbor Docker Registry configured to use shared storage (e.g. NFS, Ceph etc.)? [yes/no]:'
					if raw_input(msg).lower() != "yes":
						raise Exception(
							"Error: In HA mode, shared storage configuration for Docker Registry in harbor.cfg is required. Refer to HA installation guide for details."
						)
				redis_url = rcp.get("configuration", "redis_url")
				if redis_url is None or len(redis_url) < 1:
					raise Exception(
						"Error: In HA mode, redis_url in harbor.cfg needs to point to a Redis cluster."
					)
				if args.notary_mode:
					raise Exception("Error: HA mode doesn't support Notary currently")
				if args.clair_mode:
					clair_db_host = rcp.get("configuration", "clair_db_host")
					if "postgres" == clair_db_host:
						raise Exception(
							"Error: In HA mode, clair_db_host in harbor.cfg needs to point to an external Postgres DB address."
						)

				cert_path = rcp.get("configuration", "ssl_cert")
				cert_key_path = rcp.get("configuration", "ssl_cert_key")
				shared_cert_key = os.path.join(base_dir, "ha",
											   os.path.basename(cert_key_path))
				shared_cert_path = os.path.join(base_dir, "ha",
												os.path.basename(cert_path))
				if os.path.isfile(shared_cert_key):
					shutil.copy2(shared_cert_key, cert_key_path)
				if os.path.isfile(shared_cert_path):
					shutil.copy2(shared_cert_path, cert_path)

			protocol = rcp.get("configuration", "ui_url_protocol")
			if protocol != "https" and args.notary_mode:
				raise Exception(
					"Error: the protocol must be https when Harbor is deployed with Notary"
				)
			if protocol == "https":
				if not rcp.has_option("configuration", "ssl_cert"):
					raise Exception(
						"Error: The protocol is https but attribute ssl_cert is not set"
					)
				cert_path = rcp.get("configuration", "ssl_cert")
				if not os.path.isfile(cert_path):
					raise Exception(
						"Error: The path for certificate: %s is invalid" % cert_path)
				if not rcp.has_option("configuration", "ssl_cert_key"):
					raise Exception(
						"Error: The protocol is https but attribute ssl_cert_key is not set"
					)
				cert_key_path = rcp.get("configuration", "ssl_cert_key")
				if not os.path.isfile(cert_key_path):
					raise Exception(
						"Error: The path for certificate key: %s is invalid" %
						cert_key_path)
			project_creation = rcp.get("configuration", "project_creation_restriction")

			if project_creation != "everyone" and project_creation != "adminonly":
				raise Exception(
					"Error invalid value for project_creation_restriction: %s" %
					project_creation)

		def prepare_ha(conf, args):
			#files under ha folder will have high prority
			protocol = rcp.get("configuration", "ui_url_protocol")
			if protocol == "https":
				#copy nginx certificate
				cert_path = rcp.get("configuration", "ssl_cert")
				cert_key_path = rcp.get("configuration", "ssl_cert_key")
				shared_cert_key = os.path.join(base_dir, "ha",
											   os.path.basename(cert_key_path))
				shared_cert_path = os.path.join(base_dir, "ha",
												os.path.basename(cert_path))
				if os.path.isfile(shared_cert_key):
					shutil.copy2(shared_cert_key, cert_key_path)
				else:
					if os.path.isfile(cert_key_path):
						shutil.copy2(cert_key_path, shared_cert_key)
				if os.path.isfile(shared_cert_path):
					shutil.copy2(shared_cert_path, cert_path)
				else:
					if os.path.isfile(cert_path):
						shutil.copy2(cert_path, shared_cert_path)
				#check if ca exsit
				cert_ca_path = "/data/ca_download/ca.crt"
				shared_ca_path = os.path.join(base_dir, "ha",
											  os.path.basename(cert_ca_path))
				if os.path.isfile(shared_ca_path):
					shutil.copy2(shared_ca_path, cert_ca_path)
				else:
					if os.path.isfile(cert_ca_path):
						shutil.copy2(cert_ca_path, shared_ca_path)
			#check root.crt and priviate_key.pem
			private_key_pem = os.path.join(config_dir, "ui", "private_key.pem")
			root_crt = os.path.join(config_dir, "registry", "root.crt")
			shared_private_key_pem = os.path.join(base_dir, "ha", "private_key.pem")
			shared_root_crt = os.path.join(base_dir, "ha", "root.crt")
			if os.path.isfile(shared_private_key_pem):
				shutil.copy2(shared_private_key_pem, private_key_pem)
			else:
				if os.path.isfile(private_key_pem):
					shutil.copy2(private_key_pem, shared_private_key_pem)
			if os.path.isfile(shared_root_crt):
				shutil.copy2(shared_root_crt, root_crt)
			else:
				if os.path.isfile(root_crt):
					shutil.copy2(root_crt, shared_root_crt)
			#secretkey
			shared_secret_key = os.path.join(base_dir, "ha", "secretkey")
			secretkey_path = rcp.get("configuration", "secretkey_path")
			secret_key = os.path.join(secretkey_path, "secretkey")
			if os.path.isfile(shared_secret_key):
				shutil.copy2(shared_secret_key, secret_key)
			else:
				if os.path.isfile(secret_key):
					shutil.copy2(secret_key, shared_secret_key)

		def get_secret_key(path):
			secret_key = _get_secret(path, "secretkey")
			if len(secret_key) != 16:
				raise Exception(
					"secret key's length has to be 16 chars, current length: %d" %
					len(secret_key))
			return secret_key


		def get_alias(path):
			alias = _get_secret(path, "defaultalias", length=8)
			return alias


		def _get_secret(folder, filename, length=16):
			key_file = os.path.join(folder, filename)
			if os.path.isfile(key_file):
				with open(key_file, 'r') as f:
					key = f.read()
					print("loaded secret from file: %s" % key_file)
				return key
			if not os.path.isdir(folder):
				os.makedirs(folder, mode=0o600)
			key = ''.join(
				random.choice(string.ascii_letters + string.digits)
				for i in range(length))
			with open(key_file, 'w') as f:
				f.write(key)
				print("Generated and saved secret to file: %s" % key_file)
			os.chmod(key_file, 0o600)
			return key


		def prep_conf_dir(root, name):
			absolute_path = os.path.join(root, name)
			if not os.path.exists(absolute_path):
				os.makedirs(absolute_path)
			return absolute_path


		def render(src, dest, **kw):
			t = Template(open(src, 'r').read())
			with open(dest, 'w') as f:
				f.write(t.substitute(**kw))
			print("Generated configuration file: %s" % dest)


		base_dir = os.path.dirname(__file__)
		config_dir = os.path.join(base_dir, "common/config")
		templates_dir = os.path.join(base_dir, "common/templates")


		def delfile(src):
			if os.path.isfile(src):
				try:
					os.remove(src)
					print("Clearing the configuration file: %s" % src)
				except:
					pass
			elif os.path.isdir(src):
				for item in os.listdir(src):
					itemsrc = os.path.join(src, item)
					delfile(itemsrc)


		parser = argparse.ArgumentParser()
		parser.add_argument(
			'--conf',
			dest='cfgfile',
			default=base_dir + '/harbor.cfg',
			type=str,
			help="the path of Harbor configuration file")
		parser.add_argument(
			'--with-notary',
			dest='notary_mode',
			default=False,
			action='store_true',
			help="the Harbor instance is to be deployed with notary")
		parser.add_argument(
			'--with-clair',
			dest='clair_mode',
			default=False,
			action='store_true',
			help="the Harbor instance is to be deployed with clair")
		parser.add_argument(
			'--ha',
			dest='ha_mode',
			default=False,
			action='store_true',
			help="the Harbor instance is to be deployed in HA mode")
		parser.add_argument(
			'--yes',
			dest='yes',
			default=False,
			action='store_true',
			help="Answer yes to all questions")
		args = parser.parse_args()

		delfile(config_dir)
		#Read configurations
		conf = StringIO.StringIO()
		conf.write("[configuration]\n")
		conf.write(open(args.cfgfile).read())
		conf.seek(0, os.SEEK_SET)
		rcp = ConfigParser.RawConfigParser()
		rcp.readfp(conf)
		validate(rcp, args)

		reload_config = rcp.get("configuration", "reload_config") if rcp.has_option(
			"configuration", "reload_config") else "false"
		hostname = rcp.get("configuration", "hostname")
		protocol = rcp.get("configuration", "ui_url_protocol")
		public_url = protocol + "://" + hostname
		email_identity = rcp.get("configuration", "email_identity")
		email_host = rcp.get("configuration", "email_server")
		email_port = rcp.get("configuration", "email_server_port")
		email_usr = rcp.get("configuration", "email_username")
		email_pwd = rcp.get("configuration", "email_password")
		email_from = rcp.get("configuration", "email_from")
		email_ssl = rcp.get("configuration", "email_ssl")
		email_insecure = rcp.get("configuration", "email_insecure")
		harbor_admin_password = rcp.get("configuration", "harbor_admin_password")
		auth_mode = rcp.get("configuration", "auth_mode")
		ldap_url = rcp.get("configuration", "ldap_url")
		# this two options are either both set or unset
		if rcp.has_option("configuration", "ldap_searchdn"):
			ldap_searchdn = rcp.get("configuration", "ldap_searchdn")
			ldap_search_pwd = rcp.get("configuration", "ldap_search_pwd")
		else:
			ldap_searchdn = ""
			ldap_search_pwd = ""
		ldap_basedn = rcp.get("configuration", "ldap_basedn")
		# ldap_filter is null by default
		if rcp.has_option("configuration", "ldap_filter"):
			ldap_filter = rcp.get("configuration", "ldap_filter")
		else:
			ldap_filter = ""
		ldap_uid = rcp.get("configuration", "ldap_uid")
		ldap_scope = rcp.get("configuration", "ldap_scope")
		ldap_timeout = rcp.get("configuration", "ldap_timeout")
		ldap_verify_cert = rcp.get("configuration", "ldap_verify_cert")
		ldap_group_basedn = rcp.get("configuration", "ldap_group_basedn")
		ldap_group_filter = rcp.get("configuration", "ldap_group_filter")
		ldap_group_gid = rcp.get("configuration", "ldap_group_gid")
		ldap_group_scope = rcp.get("configuration", "ldap_group_scope")
		db_password = rcp.get("configuration", "db_password")
		db_host = rcp.get("configuration", "db_host")
		db_user = rcp.get("configuration", "db_user")
		db_port = rcp.get("configuration", "db_port")
		self_registration = rcp.get("configuration", "self_registration")
		if protocol == "https":
			cert_path = rcp.get("configuration", "ssl_cert")
			cert_key_path = rcp.get("configuration", "ssl_cert_key")
		customize_crt = rcp.get("configuration", "customize_crt")
		max_job_workers = rcp.get("configuration", "max_job_workers")
		token_expiration = rcp.get("configuration", "token_expiration")
		proj_cre_restriction = rcp.get("configuration", "project_creation_restriction")
		secretkey_path = rcp.get("configuration", "secretkey_path")
		if rcp.has_option("configuration", "admiral_url"):
			admiral_url = rcp.get("configuration", "admiral_url")
		else:
			admiral_url = ""
		clair_db_password = rcp.get("configuration", "clair_db_password")
		clair_db_host = rcp.get("configuration", "clair_db_host")
		clair_db_port = rcp.get("configuration", "clair_db_port")
		clair_db_username = rcp.get("configuration", "clair_db_username")
		clair_db = rcp.get("configuration", "clair_db")

		uaa_endpoint = rcp.get("configuration", "uaa_endpoint")
		uaa_clientid = rcp.get("configuration", "uaa_clientid")
		uaa_clientsecret = rcp.get("configuration", "uaa_clientsecret")
		uaa_verify_cert = rcp.get("configuration", "uaa_verify_cert")
		uaa_ca_cert = rcp.get("configuration", "uaa_ca_cert")

		secret_key = get_secret_key(secretkey_path)
		log_rotate_count = rcp.get("configuration", "log_rotate_count")
		log_rotate_size = rcp.get("configuration", "log_rotate_size")

		if rcp.has_option("configuration", "redis_url"):
			redis_url = rcp.get("configuration", "redis_url")
		else:
			redis_url = ""

		storage_provider_name = rcp.get("configuration",
										"registry_storage_provider_name").strip()
		storage_provider_config = rcp.get("configuration",
										  "registry_storage_provider_config").strip()
		# yaml requires 1 or more spaces between the key and value
		storage_provider_config = storage_provider_config.replace(":", ": ", 1)
		ui_secret = ''.join(
			random.choice(string.ascii_letters + string.digits) for i in range(16))
		jobservice_secret = ''.join(
			random.choice(string.ascii_letters + string.digits) for i in range(16))

		adminserver_config_dir = os.path.join(config_dir, "adminserver")
		if not os.path.exists(adminserver_config_dir):
			os.makedirs(os.path.join(config_dir, "adminserver"))

		ui_config_dir = prep_conf_dir(config_dir, "ui")
		ui_certificates_dir = prep_conf_dir(ui_config_dir, "certificates")
		db_config_dir = prep_conf_dir(config_dir, "db")
		job_config_dir = prep_conf_dir(config_dir, "jobservice")
		registry_config_dir = prep_conf_dir(config_dir, "registry")
		nginx_config_dir = prep_conf_dir(config_dir, "nginx")
		nginx_conf_d = prep_conf_dir(nginx_config_dir, "conf.d")
		log_config_dir = prep_conf_dir(config_dir, "log")

		adminserver_conf_env = os.path.join(config_dir, "adminserver", "env")
		ui_conf_env = os.path.join(config_dir, "ui", "env")
		ui_conf = os.path.join(config_dir, "ui", "app.conf")
		ui_cert_dir = os.path.join(config_dir, "ui", "certificates")
		jobservice_conf = os.path.join(config_dir, "jobservice", "config.yml")
		registry_conf = os.path.join(config_dir, "registry", "config.yml")
		db_conf_env = os.path.join(config_dir, "db", "env")
		job_conf_env = os.path.join(config_dir, "jobservice", "env")
		nginx_conf = os.path.join(config_dir, "nginx", "nginx.conf")
		cert_dir = os.path.join(config_dir, "nginx", "cert")
		log_rotate_config = os.path.join(config_dir, "log", "logrotate.conf")
		adminserver_url = "http://adminserver:8080"
		registry_url = "http://registry:5000"
		ui_url = "http://ui:8080"
		token_service_url = "http://ui:8080/service/token"

		jobservice_url = "http://jobservice:8080"
		clair_url = "http://clair:6060"
		notary_url = "http://notary-server:4443"

		if protocol == "https":
			target_cert_path = os.path.join(cert_dir, os.path.basename(cert_path))
			if not os.path.exists(cert_dir):
				os.makedirs(cert_dir)
			shutil.copy2(cert_path, target_cert_path)
			target_cert_key_path = os.path.join(cert_dir,
												os.path.basename(cert_key_path))
			shutil.copy2(cert_key_path, target_cert_key_path)
			render(
				os.path.join(templates_dir, "nginx", "nginx.https.conf"),
				nginx_conf,
				ssl_cert=os.path.join("/etc/nginx/cert",
									  os.path.basename(target_cert_path)),
				ssl_cert_key=os.path.join("/etc/nginx/cert",
										  os.path.basename(target_cert_key_path)))
		else:
			render(os.path.join(templates_dir, "nginx", "nginx.http.conf"), nginx_conf)

		render(
			os.path.join(templates_dir, "adminserver", "env"),
			adminserver_conf_env,
			reload_config=reload_config,
			public_url=public_url,
			ui_url=ui_url,
			auth_mode=auth_mode,
			self_registration=self_registration,
			ldap_url=ldap_url,
			ldap_searchdn=ldap_searchdn,
			ldap_search_pwd=ldap_search_pwd,
			ldap_basedn=ldap_basedn,
			ldap_filter=ldap_filter,
			ldap_uid=ldap_uid,
			ldap_scope=ldap_scope,
			ldap_verify_cert=ldap_verify_cert,
			ldap_timeout=ldap_timeout,
			ldap_group_basedn=ldap_group_basedn,
			ldap_group_filter=ldap_group_filter,
			ldap_group_gid=ldap_group_gid,
			ldap_group_scope=ldap_group_scope,
			db_password=db_password,
			db_host=db_host,
			db_user=db_user,
			db_port=db_port,
			email_host=email_host,
			email_port=email_port,
			email_usr=email_usr,
			email_pwd=email_pwd,
			email_ssl=email_ssl,
			email_insecure=email_insecure,
			email_from=email_from,
			email_identity=email_identity,
			harbor_admin_password=harbor_admin_password,
			project_creation_restriction=proj_cre_restriction,
			max_job_workers=max_job_workers,
			ui_secret=ui_secret,
			jobservice_secret=jobservice_secret,
			token_expiration=token_expiration,
			admiral_url=admiral_url,
			with_notary=args.notary_mode,
			with_clair=args.clair_mode,
			clair_db_password=clair_db_password,
			clair_db_host=clair_db_host,
			clair_db_port=clair_db_port,
			clair_db_username=clair_db_username,
			clair_db=clair_db,
			uaa_endpoint=uaa_endpoint,
			uaa_clientid=uaa_clientid,
			uaa_clientsecret=uaa_clientsecret,
			uaa_verify_cert=uaa_verify_cert,
			storage_provider_name=storage_provider_name,
			registry_url=registry_url,
			token_service_url=token_service_url,
			jobservice_url=jobservice_url,
			clair_url=clair_url,
			notary_url=notary_url)

		render(
			os.path.join(templates_dir, "ui", "env"),
			ui_conf_env,
			ui_secret=ui_secret,
			jobservice_secret=jobservice_secret,
			redis_url=redis_url,
			adminserver_url=adminserver_url)

		registry_config_file = "config_ha.yml" if args.ha_mode else "config.yml"
		if storage_provider_name == "filesystem":
			if not storage_provider_config:
				storage_provider_config = "rootdirectory: /storage"
			elif "rootdirectory:" not in storage_provider_config:
				storage_provider_config = "rootdirectory: /storage" + "," + storage_provider_config
		# generate storage configuration section in yaml format
		storage_provider_info = (
			'\n' + ' ' * 4).join([storage_provider_name + ':'] +
								 map(string.strip, storage_provider_config.split(",")))
		render(
			os.path.join(templates_dir, "registry", registry_config_file),
			registry_conf,
			storage_provider_info=storage_provider_info,
			public_url=public_url,
			ui_url=ui_url,
			redis_url=redis_url)

		render(
			os.path.join(templates_dir, "db", "env"),
			db_conf_env,
			db_password=db_password)

		render(
			os.path.join(templates_dir, "jobservice", "env"),
			job_conf_env,
			ui_secret=ui_secret,
			jobservice_secret=jobservice_secret,
			adminserver_url=adminserver_url)

		render(
			os.path.join(templates_dir, "jobservice", "config.yml"),
			jobservice_conf,
			max_job_workers=max_job_workers,
			redis_url=redis_url)

		render(
			os.path.join(templates_dir, "log", "logrotate.conf"),
			log_rotate_config,
			log_rotate_count=log_rotate_count,
			log_rotate_size=log_rotate_size)

		print("Generated configuration file: %s" % jobservice_conf)

		print("Generated configuration file: %s" % ui_conf)
		shutil.copyfile(os.path.join(templates_dir, "ui", "app.conf"), ui_conf)

		if auth_mode == "uaa_auth":
			if os.path.isfile(uaa_ca_cert):
				if not os.path.isdir(ui_cert_dir):
					os.makedirs(ui_cert_dir, mode=0o600)
				ui_uaa_ca = os.path.join(ui_cert_dir, "uaa_ca.pem")
				print("Copying UAA CA cert to %s" % ui_uaa_ca)
				shutil.copyfile(uaa_ca_cert, ui_uaa_ca)
			else:
				print("Can not find UAA CA cert: %s, skip" % uaa_ca_cert)


		def validate_crt_subj(dirty_subj):
			subj_list = [item for item in dirty_subj.strip().split("/") \
			 if len(item.split("=")) == 2 and len(item.split("=")[1]) > 0]
			return "/" + "/".join(subj_list)


		FNULL = open(os.devnull, 'w')

		from functools import wraps


		def stat_decorator(func):
			@wraps(func)
			def check_wrapper(*args, **kw):
				stat = func(*args, **kw)
				message = "Generated certificate, key file: %s, cert file: %s" % (kw['key_path'], kw['cert_path']) \
				  if stat == 0 else "Fail to generate key file: %s, cert file: %s" % (kw['key_path'], kw['cert_path'])
				print(message)
				if stat != 0:
					sys.exit(1)

			return check_wrapper


		@stat_decorator
		def create_root_cert(subj, key_path="./k.key", cert_path="./cert.crt"):
			rc = subprocess.call(
				["openssl", "genrsa", "-out", key_path, "4096"],
				stdout=FNULL,
				stderr=subprocess.STDOUT)
			if rc != 0:
				return rc
			return subprocess.call(["openssl", "req", "-new", "-x509", "-key", key_path,\
			  "-out", cert_path, "-days", "3650", "-subj", subj], stdout=FNULL, stderr=subprocess.STDOUT)


		@stat_decorator
		def create_cert(subj,
						ca_key,
						ca_cert,
						key_path="./k.key",
						cert_path="./cert.crt"):
			cert_dir = os.path.dirname(cert_path)
			csr_path = os.path.join(cert_dir, "tmp.csr")
			rc = subprocess.call(["openssl", "req", "-newkey", "rsa:4096", "-nodes","-sha256","-keyout", key_path,\
			 "-out", csr_path, "-subj", subj], stdout=FNULL, stderr=subprocess.STDOUT)
			if rc != 0:
				return rc
			return subprocess.call(["openssl", "x509", "-req", "-days", "3650", "-in", csr_path, "-CA", \
			 ca_cert, "-CAkey", ca_key, "-CAcreateserial", "-out", cert_path], stdout=FNULL, stderr=subprocess.STDOUT)


		def openssl_installed():
			shell_stat = subprocess.check_call(
				["which", "openssl"], stdout=FNULL, stderr=subprocess.STDOUT)
			if shell_stat != 0:
				print(
					"Cannot find openssl installed in this computer\nUse default SSL certificate file"
				)
				return False
			return True


		if customize_crt == 'on' and openssl_installed():
			shell_stat = subprocess.check_call(
				["which", "openssl"], stdout=FNULL, stderr=subprocess.STDOUT)
			empty_subj = "/C=/ST=/L=/O=/CN=/"
			private_key_pem = os.path.join(config_dir, "ui", "private_key.pem")
			root_crt = os.path.join(config_dir, "registry", "root.crt")
			create_root_cert(empty_subj, key_path=private_key_pem, cert_path=root_crt)
			os.chmod(private_key_pem, 0o600)
			os.chmod(root_crt, 0o600)
		else:
			print("Copied configuration file: %s" % ui_config_dir + "private_key.pem")
			shutil.copyfile(
				os.path.join(templates_dir, "ui", "private_key.pem"),
				os.path.join(ui_config_dir, "private_key.pem"))
			print("Copied configuration file: %s" % registry_config_dir + "root.crt")
			shutil.copyfile(
				os.path.join(templates_dir, "registry", "root.crt"),
				os.path.join(registry_config_dir, "root.crt"))

		if args.notary_mode:
			notary_config_dir = prep_conf_dir(config_dir, "notary")
			notary_temp_dir = os.path.join(templates_dir, "notary")
			print("Copying sql file for notary DB")
			if os.path.exists(os.path.join(notary_config_dir, "mysql-initdb.d")):
				shutil.rmtree(os.path.join(notary_config_dir, "mysql-initdb.d"))
			shutil.copytree(
				os.path.join(notary_temp_dir, "mysql-initdb.d"),
				os.path.join(notary_config_dir, "mysql-initdb.d"))
			if customize_crt == 'on' and openssl_installed():
				try:
					temp_cert_dir = os.path.join(base_dir, "cert_tmp")
					if not os.path.exists(temp_cert_dir):
						os.makedirs(temp_cert_dir)
					ca_subj = "/C=US/ST=California/L=Palo Alto/O=VMware, Inc./OU=Harbor/CN=Self-signed by VMware, Inc."
					cert_subj = "/C=US/ST=California/L=Palo Alto/O=VMware, Inc./OU=Harbor/CN=notarysigner"
					signer_ca_cert = os.path.join(temp_cert_dir,
												  "notary-signer-ca.crt")
					signer_ca_key = os.path.join(temp_cert_dir, "notary-signer-ca.key")
					signer_cert_path = os.path.join(temp_cert_dir, "notary-signer.crt")
					signer_key_path = os.path.join(temp_cert_dir, "notary-signer.key")
					create_root_cert(
						ca_subj, key_path=signer_ca_key, cert_path=signer_ca_cert)
					create_cert(
						cert_subj,
						signer_ca_key,
						signer_ca_cert,
						key_path=signer_key_path,
						cert_path=signer_cert_path)
					print("Copying certs for notary signer")
					os.chmod(signer_cert_path, 0o600)
					os.chmod(signer_key_path, 0o600)
					os.chmod(signer_ca_cert, 0o600)
					shutil.copy2(signer_cert_path, notary_config_dir)
					shutil.copy2(signer_key_path, notary_config_dir)
					shutil.copy2(signer_ca_cert, notary_config_dir)
				finally:
					srl_tmp = os.path.join(os.getcwd(), ".srl")
					if os.path.isfile(srl_tmp):
						os.remove(srl_tmp)
					if os.path.isdir(temp_cert_dir):
						shutil.rmtree(temp_cert_dir, True)
			else:
				print("Copying certs for notary signer")
				shutil.copy2(
					os.path.join(notary_temp_dir, "notary-signer.crt"),
					notary_config_dir)
				shutil.copy2(
					os.path.join(notary_temp_dir, "notary-signer.key"),
					notary_config_dir)
				shutil.copy2(
					os.path.join(notary_temp_dir, "notary-signer-ca.crt"),
					notary_config_dir)
			shutil.copy2(
				os.path.join(registry_config_dir, "root.crt"), notary_config_dir)
			print("Copying notary signer configuration file")
			shutil.copy2(
				os.path.join(notary_temp_dir, "signer-config.json"), notary_config_dir)
			render(
				os.path.join(notary_temp_dir, "server-config.json"),
				os.path.join(notary_config_dir, "server-config.json"),
				token_endpoint=public_url)

			print("Copying nginx configuration file for notary")
			shutil.copy2(
				os.path.join(templates_dir, "nginx", "notary.upstream.conf"),
				nginx_conf_d)
			render(
				os.path.join(templates_dir, "nginx", "notary.server.conf"),
				os.path.join(nginx_conf_d, "notary.server.conf"),
				ssl_cert=os.path.join("/etc/nginx/cert",
									  os.path.basename(target_cert_path)),
				ssl_cert_key=os.path.join("/etc/nginx/cert",
										  os.path.basename(target_cert_key_path)))

			default_alias = get_alias(secretkey_path)
			render(
				os.path.join(notary_temp_dir, "signer_env"),
				os.path.join(notary_config_dir, "signer_env"),
				alias=default_alias)

		if args.clair_mode:
			clair_temp_dir = os.path.join(templates_dir, "clair")
			clair_config_dir = prep_conf_dir(config_dir, "clair")
			if os.path.exists(os.path.join(clair_config_dir, "postgresql-init.d")):
				print("Copying offline data file for clair DB")
				shutil.rmtree(os.path.join(clair_config_dir, "postgresql-init.d"))
			shutil.copytree(
				os.path.join(clair_temp_dir, "postgresql-init.d"),
				os.path.join(clair_config_dir, "postgresql-init.d"))
			postgres_env = os.path.join(clair_config_dir, "postgres_env")
			render(
				os.path.join(clair_temp_dir, "postgres_env"),
				postgres_env,
				password=clair_db_password)
			clair_conf = os.path.join(clair_config_dir, "config.yaml")
			render(
				os.path.join(clair_temp_dir, "config.yaml"),
				clair_conf,
				password=clair_db_password,
				username=clair_db_username,
				host=clair_db_host,
				port=clair_db_port,
				dbname=clair_db)

			# config http proxy for Clair
			http_proxy = rcp.get("configuration", "http_proxy").strip()
			https_proxy = rcp.get("configuration", "https_proxy").strip()
			no_proxy = rcp.get("configuration", "no_proxy").strip()
			clair_env = os.path.join(clair_config_dir, "clair_env")
			render(
				os.path.join(clair_temp_dir, "clair_env"),
				clair_env,
				http_proxy=http_proxy,
				https_proxy=https_proxy,
				no_proxy=no_proxy)

		if args.ha_mode:
			prepare_ha(rcp, args)

		FNULL.close()
		print(
			"The configuration files are ready, please use docker-compose to start the service."
		)

	`)))

	HarborDockerComposeTempl = template.Must(template.New("harbor").Parse(dedent.Dedent(`
        version: '2'
        services:
          log:
            image: vmware/harbor-log:v1.5.0
            container_name: harbor-log
            restart: always
            volumes:
              - /var/log/harbor/:/var/log/docker/:z
              - ./common/config/log/:/etc/logrotate.d/:z
            ports:
              - 127.0.0.1:1514:10514
            networks:
              - harbor
          registry:
            image: vmware/registry-photon:v2.6.2-v1.5.0
            container_name: registry
            restart: always
            volumes:
              - /data/registry:/storage:z
              - ./common/config/registry/:/etc/registry/:z
            networks:
              - harbor
            environment:
              - GODEBUG=netdns=cgo
            command:
              ["serve", "/etc/registry/config.yml"]
            depends_on:
              - log
            logging:
              driver: "syslog"
              options:
                syslog-address: "tcp://127.0.0.1:1514"
                tag: "registry"
          mysql:
            image: vmware/harbor-db:v1.5.0
            container_name: harbor-db
            restart: always
            volumes:
              - /data/database:/var/lib/mysql:z
            networks:
              - harbor
            env_file:
              - ./common/config/db/env
            depends_on:
              - log
            logging:
              driver: "syslog"
              options:
                syslog-address: "tcp://127.0.0.1:1514"
                tag: "mysql"
          adminserver:
            image: vmware/harbor-adminserver:v1.5.0
            container_name: harbor-adminserver
            env_file:
              - ./common/config/adminserver/env
            restart: always
            volumes:
              - /data/config/:/etc/adminserver/config/:z
              - /data/secretkey:/etc/adminserver/key:z
              - /data/:/data/:z
            networks:
              - harbor
            depends_on:
              - log
            logging:
              driver: "syslog"
              options:
                syslog-address: "tcp://127.0.0.1:1514"
                tag: "adminserver"
          ui:
            image: vmware/harbor-ui:v1.5.0
            container_name: harbor-ui
            env_file:
              - ./common/config/ui/env
            restart: always
            volumes:
              - ./common/config/ui/app.conf:/etc/ui/app.conf:z
              - ./common/config/ui/private_key.pem:/etc/ui/private_key.pem:z
              - ./common/config/ui/certificates/:/etc/ui/certificates/:z
              - /data/secretkey:/etc/ui/key:z
              - /data/ca_download/:/etc/ui/ca/:z
              - /data/psc/:/etc/ui/token/:z
            networks:
              - harbor
            depends_on:
              - log
              - adminserver
              - registry
            logging:
              driver: "syslog"
              options:
                syslog-address: "tcp://127.0.0.1:1514"
                tag: "ui"
          jobservice:
            image: vmware/harbor-jobservice:v1.5.0
            container_name: harbor-jobservice
            env_file:
              - ./common/config/jobservice/env
            restart: always
            volumes:
              - /data/job_logs:/var/log/jobs:z
              - ./common/config/jobservice/config.yml:/etc/jobservice/config.yml:z
            networks:
              - harbor
            depends_on:
              - redis
              - ui
              - adminserver
            logging:
              driver: "syslog"
              options:
                syslog-address: "tcp://127.0.0.1:1514"
                tag: "jobservice"
          redis:
            image: vmware/redis-photon:v1.5.0
            container_name: redis
            restart: always
            volumes:
              - /data/redis:/data
            networks:
              - harbor
            depends_on:
              - log
            logging:
              driver: "syslog"
              options:
                syslog-address: "tcp://127.0.0.1:1514"
                tag: "redis"
          proxy:
            image: vmware/nginx-photon:v1.5.0
            container_name: nginx
            restart: always
            volumes:
              - ./common/config/nginx:/etc/nginx:z
            networks:
              - harbor
            ports:
              - 80:80
              - 443:443
              - 4443:4443
            depends_on:
              - mysql
              - registry
              - ui
              - log
            logging:
              driver: "syslog"
              options:
                syslog-address: "tcp://127.0.0.1:1514"
                tag: "proxy"
        networks:
          harbor:
            external: false



	`)))

	HarborAdminServerEnvTempl = template.Must(template.New("harbor").Parse(dedent.Dedent(`
		PORT=8080
		LOG_LEVEL=info
		EXT_ENDPOINT=$public_url
		AUTH_MODE=$auth_mode
		SELF_REGISTRATION=$self_registration
		LDAP_URL=$ldap_url
		LDAP_SEARCH_DN=$ldap_searchdn
		LDAP_SEARCH_PWD=$ldap_search_pwd
		LDAP_BASE_DN=$ldap_basedn
		LDAP_FILTER=$ldap_filter
		LDAP_UID=$ldap_uid
		LDAP_SCOPE=$ldap_scope
		LDAP_TIMEOUT=$ldap_timeout
		LDAP_VERIFY_CERT=$ldap_verify_cert
		LDAP_GROUP_BASEDN=$ldap_group_basedn
		LDAP_GROUP_FILTER=$ldap_group_filter
		LDAP_GROUP_GID=$ldap_group_gid
		LDAP_GROUP_SCOPE=$ldap_group_scope
		DATABASE_TYPE=mysql
		MYSQL_HOST=$db_host
		MYSQL_PORT=$db_port
		MYSQL_USR=$db_user
		MYSQL_PWD=$db_password
		MYSQL_DATABASE=registry
		REGISTRY_URL=$registry_url
		TOKEN_SERVICE_URL=$token_service_url
		EMAIL_HOST=$email_host
		EMAIL_PORT=$email_port
		EMAIL_USR=$email_usr
		EMAIL_PWD=$email_pwd
		EMAIL_SSL=$email_ssl
		EMAIL_FROM=$email_from
		EMAIL_IDENTITY=$email_identity
		EMAIL_INSECURE=$email_insecure
		HARBOR_ADMIN_PASSWORD=$harbor_admin_password
		PROJECT_CREATION_RESTRICTION=$project_creation_restriction
		MAX_JOB_WORKERS=$max_job_workers
		UI_SECRET=$ui_secret
		JOBSERVICE_SECRET=$jobservice_secret
		TOKEN_EXPIRATION=$token_expiration
		CFG_EXPIRATION=5
		GODEBUG=netdns=cgo
		ADMIRAL_URL=$admiral_url
		WITH_NOTARY=$with_notary
		WITH_CLAIR=$with_clair
		CLAIR_DB_PASSWORD=$clair_db_password
		CLAIR_DB_HOST=$clair_db_host
		CLAIR_DB_PORT=$clair_db_port
		CLAIR_DB_USERNAME=$clair_db_username
		CLAIR_DB=$clair_db
		RESET=$reload_config
		UAA_ENDPOINT=$uaa_endpoint
		UAA_CLIENTID=$uaa_clientid
		UAA_CLIENTSECRET=$uaa_clientsecret
		UAA_VERIFY_CERT=$uaa_verify_cert
		UI_URL=$ui_url
		JOBSERVICE_URL=$jobservice_url
		CLAIR_URL=$clair_url
		NOTARY_URL=$notary_url
		REGISTRY_STORAGE_PROVIDER_NAME=$storage_provider_name
		READ_ONLY=false
	`)))

	HarborDBEnvTempl = template.Must(template.New("harbor").Parse(dedent.Dedent(`
		MYSQL_ROOT_PASSWORD=$db_password
	`)))

	HarborJobServerConfigTempl = template.Must(template.New("harbor").Parse(dedent.Dedent(`
    ---
    #Protocol used to serve
    protocol: "http"

    #Config certification if use 'https' protocol
    #https_config:
    #  cert: "server.crt"
    #  key: "server.key"

    #Server listening port
    port: 8080

    #Worker pool
    worker_pool:
      #Worker concurrency
      workers: $max_job_workers
      backend: "redis"
      #Additional config if use 'redis' backend
      redis_pool:
        #redis://[arbitrary_username:password@]ipaddress:port/database_index
        #or ipaddress:port[,weight,password,database_index]
        redis_url: $redis_url
        namespace: "harbor_job_service_namespace"
    #Logger for job
    logger:
      path: "/var/log/jobs"
      level: "INFO"
      archive_period: 14 #days
    #Admin server endpoint
    admin_server: "http://adminserver:8080/"

	`)))

	HarborJobServerEnvTempl = template.Must(template.New("harbor").Parse(dedent.Dedent(`
		UI_SECRET=$ui_secret
		JOBSERVICE_SECRET=$jobservice_secret
		ADMINSERVER_URL=$adminserver_url
		GODEBUG=netdns=cgo
	`)))

	HarborLogrotateConfigTempl = template.Must(template.New("harbor").Parse(dedent.Dedent(`
		/var/log/docker/*.log {
			rotate $log_rotate_count
			size $log_rotate_size
			copytruncate
			compress
			missingok
			nodateext
		}
	`)))

	HarborNginxConfigTempl = template.Must(template.New("harbor").Parse(dedent.Dedent(`
		worker_processes auto;

		events {
		worker_connections 1024;
		use epoll;
		multi_accept on;
		}

		http {
		tcp_nodelay on;
		include /etc/nginx/conf.d/*.upstream.conf;

		# this is necessary for us to be able to disable request buffering in all cases
		proxy_http_version 1.1;

		upstream registry {
			server registry:5000;
		}

		upstream ui {
			server ui:8080;
		}

		log_format timed_combined '$$remote_addr - '
			'"$$request" $$status $$body_bytes_sent '
			'"$$http_referer" "$$http_user_agent" '
			'$$request_time $$upstream_response_time $$pipe';

		access_log /dev/stdout timed_combined;

		include /etc/nginx/conf.d/*.server.conf;

		server {
			listen 443 ssl;
		#    server_name harbordomain.com;
			server_tokens off;
			# SSL
			ssl_certificate $ssl_cert;
			ssl_certificate_key $ssl_cert_key;

			# Recommendations from https://raymii.org/s/tutorials/Strong_SSL_Security_On_nginx.html
			ssl_protocols TLSv1.1 TLSv1.2;
			ssl_ciphers '!aNULL:kECDH+AESGCM:ECDH+AESGCM:RSA+AESGCM:kECDH+AES:ECDH+AES:RSA+AES:';
			ssl_prefer_server_ciphers on;
			ssl_session_cache shared:SSL:10m;

			# disable any limits to avoid HTTP 413 for large image uploads
			client_max_body_size 0;

			# required to avoid HTTP 411: see Issue #1486 (https://github.com/docker/docker/issues/1486)
			chunked_transfer_encoding on;

			location / {
			proxy_pass http://ui/;
			proxy_set_header Host $$http_host;
			proxy_set_header X-Real-IP $$remote_addr;
			proxy_set_header X-Forwarded-For $$proxy_add_x_forwarded_for;

			# When setting up Harbor behind other proxy, such as an Nginx instance, remove the below line if the proxy already has similar settings.
			proxy_set_header X-Forwarded-Proto $$scheme;

			# Add Secure flag when serving HTTPS
			proxy_cookie_path / "/; secure";

			proxy_buffering off;
			proxy_request_buffering off;
			}

			location /v1/ {
			return 404;
			}

			location /v2/ {
			proxy_pass http://ui/registryproxy/v2/;
			proxy_set_header Host $$http_host;
			proxy_set_header X-Real-IP $$remote_addr;
			proxy_set_header X-Forwarded-For $$proxy_add_x_forwarded_for;

			# When setting up Harbor behind other proxy, such as an Nginx instance, remove the below line if the proxy already has similar settings.
			proxy_set_header X-Forwarded-Proto $$scheme;
			proxy_buffering off;
			proxy_request_buffering off;
			}

			location /service/ {
			proxy_pass http://ui/service/;
			proxy_set_header Host $$http_host;
			proxy_set_header X-Real-IP $$remote_addr;
			proxy_set_header X-Forwarded-For $$proxy_add_x_forwarded_for;

			# When setting up Harbor behind other proxy, such as an Nginx instance, remove the below line if the proxy already has similar settings.
			proxy_set_header X-Forwarded-Proto $$scheme;

			proxy_buffering off;
			proxy_request_buffering off;
			}

			location /service/notifications {
			return 404;
			}
		}
			server {
			listen 80;
			#server_name harbordomain.com;
			return 301 https://$$host$$request_uri;
		}
		}

	`)))

	HarborRegistryConfigTempl = template.Must(template.New("harbor").Parse(dedent.Dedent(`
        version: 0.1
        log:
          level: info
          fields:
            service: registry
        storage:
          cache:
            layerinfo: inmemory
          $storage_provider_info
          maintenance:
            uploadpurging:
              enabled: false
          delete:
            enabled: true
        http:
          addr: :5000
          secret: placeholder
          debug:
            addr: localhost:5001
        auth:
          token:
            issuer: harbor-token-issuer
            realm: $public_url/service/token
            rootcertbundle: /etc/registry/root.crt
            service: harbor-registry
        notifications:
          endpoints:
          - name: harbor
            disabled: false
            url: $ui_url/service/notifications
            timeout: 3000ms
            threshold: 5
            backoff: 1s

        `)))

        HarborUIAppTempl = template.Must(template.New("harbor").Parse(dedent.Dedent(`
            appname = Harbor
            runmode = dev
            enablegzip = true

            [dev]
            httpport = 8080

	`)))

	HarborUIEnvTempl = template.Must(template.New("harbor").Parse(dedent.Dedent(`
		LOG_LEVEL=info
		CONFIG_PATH=/etc/ui/app.conf
		UI_SECRET=$ui_secret
		JOBSERVICE_SECRET=$jobservice_secret
		GODEBUG=netdns=cgo
		ADMINSERVER_URL=$adminserver_url
		UAA_CA_ROOT=/etc/ui/certificates/uaa_ca.pem
		_REDIS_URL=$redis_url
	`)))
)
