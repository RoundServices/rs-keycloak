#!/usr/bin/env python3

import os
import sys
from rs.utils.basics import Logger
from rs.utils.basics import Properties
sys.path.insert(1, '../rs/keycloak/')
from keycloak_lib import RSKeycloakAdmin


def main(arguments):
	logger = Logger(os.path.basename(__file__), "TRACE", "./setup.log")
	local_properties = Properties("./local.properties", "./local.properties")
	run(logger, local_properties)
	logger.info("{} finished.".format(os.path.basename(__file__)))


def run(logger, local_properties):
	keycloak_master_url = "http://localhost:8080/auth/"
	custom_realm = "testrealm"
	keycloak_user = "admin"
	keycloak_password = "admin"
	temp_file = "./temp.json"

	logger.debug("Connecting to master realm")
	master_admin = RSKeycloakAdmin(logger=logger, local_properties=local_properties, server_url=keycloak_master_url, username=keycloak_user, password=keycloak_password, realm_name="master")

	logger.debug("Importing realm")
	master_admin.rs_create_realm("./objects/realm.json", temp_file)

	logger.debug("Connecting to custom realm: {}", custom_realm)
	custom_admin = RSKeycloakAdmin(logger=logger, local_properties=local_properties, server_url=keycloak_master_url, username=keycloak_user, password=keycloak_password, user_realm_name="master", realm_name=custom_realm)

	custom_admin.rs_import_authentication_flows("./objects/authenticationFlows", temp_file)

	custom_admin.rs_update_realm_attributes("./objects/realmAttributes", custom_realm, temp_file)

	custom_admin.rs_import_components("./objects/components", custom_realm, temp_file)

	custom_admin.rs_import_client_scopes("./objects/clientScopes", temp_file)

	custom_admin.rs_import_clients("./objects/clients", temp_file)




if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
