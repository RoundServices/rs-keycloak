# rs-keycloak is available under the MIT License. https://github.com/RoundServices/rs-keycloak/
# Copyright (c) 2022, Round Services LLC - https://roundservices.biz/
#
# Author: Gustavo J Gallardo - ggallard@roundservices.biz
#

import json
import os
import shutil
from keycloak import KeycloakAdmin
# needed for override methods
from keycloak.exceptions import raise_error_from_response, KeycloakGetError
from keycloak.urls_patterns import URL_ADMIN_CLIENT, URL_ADMIN_FLOWS, URL_ADMIN_FLOWS_EXECUTIONS, URL_ADMIN_IDP, URL_ADMIN_REALM, URL_ADMIN_CLIENT_SCOPES_ADD_MAPPER

URL_ADMIN_CLIENT_SERVICE_ACCOUNT_USER = URL_ADMIN_CLIENT + "/service-account-user"
URL_ADMIN_DEFAULT_DEFAULT_CLIENT_SCOPES = URL_ADMIN_REALM + "/default-default-client-scopes"
URL_ADMIN_DEFAULT_DEFAULT_CLIENT_SCOPE = URL_ADMIN_DEFAULT_DEFAULT_CLIENT_SCOPES + "/{id}"
URL_ADMIN_DEFAULT_OPTIONAL_CLIENT_SCOPES = URL_ADMIN_REALM + "/default-optional-client-scopes"
URL_ADMIN_DEFAULT_OPTIONAL_CLIENT_SCOPE = URL_ADMIN_DEFAULT_OPTIONAL_CLIENT_SCOPES + "/{id}"
URL_ADMIN_EXECUTION = "admin/realms/{realm-name}/authentication/executions/{id}"
URL_ADMIN_EXECUTION_CONFIG = URL_ADMIN_EXECUTION + "/config"
URL_ADMIN_FLOW = URL_ADMIN_FLOWS + "/{id}"
URL_ADMIN_FLOWS_EXECUTION = URL_ADMIN_FLOWS_EXECUTIONS + "/execution"
URL_ADMIN_FLOWS_EXECUTIONS_FLOW = URL_ADMIN_FLOWS_EXECUTIONS + "/flow"


class RSKeycloakAdmin(KeycloakAdmin):
	def __init__(self, logger, local_properties, server_url, username=None, password=None, realm_name='master', client_id='admin-cli', verify=True, client_secret_key=None, custom_headers=None, user_realm_name=None, auto_refresh_token=None):
		KeycloakAdmin.__init__(self, server_url, username, password, realm_name, client_id, verify, client_secret_key, custom_headers, user_realm_name, auto_refresh_token)
		self.logger = logger
		self.local_properties = local_properties

# ###########################
# Override methods


	# Not provided by library, branch add-basics
	def get_realm(self):
		"""
		Return realm

		RealmRepresentation:
		https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_realmrepresentation

		:return: RealmRepresentation
		"""
		params_path = {"realm-name": self.realm_name}
		data_raw = self.raw_get(URL_ADMIN_REALM.format(**params_path))
		return raise_error_from_response(data_raw, KeycloakGetError)


	# Not provided by library, branch add-basics
	def get_client_scope_id(self, client_scope_name):
		"""
		Get internal keycloak client id from clientScope.
		This is required for further actions against this clientScope.

		:param client_scope_name: name in ClientScopeRepresentation
		https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_clientscoperepresentation
		:return: client_scope_id (uuid as string)
		"""

		client_scopes = self.get_client_scopes()
		for client_scope in client_scopes:
			if client_scope_name == client_scope['name']:
				return client_scope["id"]
		return None


	# this method returns the execution id
	def create_authentication_flow_execution(self, payload, flow_alias):
		"""
		Create a new authentication flow execution

		AuthenticationExecutionInfoRepresentation
		https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_authenticationexecutioninforepresentation

		:param payload: AuthenticationExecutionInfoRepresentation
		:param skip_exists: If true then do not raise an error if authentication execution flow already exists
		:return: Keycloak server response (AuthenticationExecutionInfoRepresentation)
		"""
		params_path = {"realm-name": self.realm_name, "flow-alias": flow_alias}
		data_raw = self.raw_post(URL_ADMIN_FLOWS_EXECUTION.format(**params_path), data=json.dumps(payload))
		raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])
		return data_raw.headers['Location'].split('/')[-1]


	# library provides get/update/delete, but not create
	def create_authenticator_config(self, payload, execution_id, skip_exists=False):
		"""
		Create a new authenticator configuration

		AuthenticatorConfigRepresentation
		https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_authenticatorconfigrepresentation

		:param payload: AuthenticatorConfigRepresentation
		:param execution_id: Authentication flow execution id
		:param skip_exists: If true then do not raise an error if authenticator config already exists
		:return: Keycloak server response (AuthenticatorConfigRepresentation)
		"""
		params_path = {"realm-name": self.realm_name, "id": execution_id}
		data_raw = self.raw_post(URL_ADMIN_EXECUTION_CONFIG.format(**params_path),
									data=json.dumps(payload))
		raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)
		return data_raw.headers['Location'].split('/')[-1]


	# method returns 202, not 204 as expected in the method in the library
	def update_authentication_flow_executions(self, payload, flow_alias):
		"""
		Update an authentication flow execution

		AuthenticationExecutionInfoRepresentation
		https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_authenticationexecutioninforepresentation

		:param payload: AuthenticationExecutionInfoRepresentation
		:param flow_alias: The flow alias
		:return: Keycloak server response
		"""
		params_path = {"realm-name": self.realm_name, "flow-alias": flow_alias}
		data_raw = self.raw_put(URL_ADMIN_FLOWS_EXECUTIONS.format(**params_path), data=json.dumps(payload))
		return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[202, 204])


	# library provides get/create/delete, but not update
	def update_idp(self, idp_alias, payload):
		"""
		Update an ID Provider

		IdentityProviderRepresentation
		https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_identityproviderrepresentation

		:param: idp_alias: idp alias name
		:param: payload: IdentityProviderRepresentation
		:return: Keycloak server response
		"""

		params_path = {"realm-name": self.realm_name, "alias": idp_alias}
		data_raw = self.raw_put(URL_ADMIN_IDP.format(**params_path),
								data=json.dumps(payload))
		return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

	def get_mappers_from_client_scope(self, client_scope_id):
		"""Get a list of all mappers connected to the client scope.
		https://www.keycloak.org/docs-api/18.0/rest-api/index.html#_protocol_mappers_resource
		:param client_scope_id: Client scope id
		:type client_scope_id: str
		:returns: Keycloak server response (ProtocolMapperRepresentation)
		:rtype: list
		"""
		params_path = {"realm-name": self.realm_name, "scope-id": client_scope_id}
		data_raw = self.raw_get(
			URL_ADMIN_CLIENT_SCOPES_ADD_MAPPER.format(**params_path)
		)
		return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[200])

# ###########################
# Added methods
	def rs_client_exists(self, client_id):
		clients = self.get_clients()
		for client in clients:
			# self.logger.trace("client: {}", client)
			# self.logger.trace("client_id: {}", client["clientId"])
			if client["clientId"] == client_id:
				return True
		return False


	def rs_get_client_keycloakid(self, client_id):
		clients = self.get_clients()
		for client in clients:
			if client_id == client.get('clientId'):
				return client["id"]
		return None


	def rs_component_exists(self, component_id, parent, provider_type):
		query = {"parent":parent, "type":provider_type}
		self.logger.trace("query: {}", query)
		components = self.get_components(query=query)
		for component in components:
			self.logger.trace("component: {}", component)
			self.logger.trace("component_id: {}", component["id"])
			if component["id"] == component_id:
				return True
		return False


	def rs_delete_component_childs(self, component_id):
		query = {"parent": component_id}
		self.logger.trace("query: {}", query)
		components = self.get_components(query=query)
		for component in components:
			self.logger.debug("Deleting component_id: {}", component["id"])
			self.delete_component(component["id"])


	def rs_idp_exists(self, idp_alias):
		idps = self.get_idps()
		for idp in idps:
			self.logger.trace("idp: {}", idp)
			self.logger.trace("idp alias: {}", idp["alias"])
			if idp["alias"] == idp_alias:
				return True
		return False


	def rs_get_authentication_flow(self, flow_alias):
		authentication_flows = self.get_authentication_flows()
		for authentication_flow in authentication_flows:
			self.logger.trace("rs_get_authentication_flow(). Searching: {}, current: {}", flow_alias, authentication_flow["alias"])
			if authentication_flow["alias"] == flow_alias:
				return authentication_flow
		self.logger.debug("rs_get_authentication_flow(). Flow '{}' not found.", flow_alias)
		return None


	def rs_get_subflow_by_id(self, flow_alias, execution_id):
		executions = self.get_authentication_flow_executions(flow_alias)
		self.logger.debug("Getting execution flow with id: {} from authentication flow: {}. Executions: {}", execution_id, flow_alias, executions)
		for execution in executions:
			self.logger.trace("rs_get_subflow_by_id(). Searching: '{}', current: '{}'.", execution_id, execution["id"])
			if "flowId" in execution:
				if execution["flowId"] == execution_id:
					return execution
		return None


	def rs_get_subflow_by_alias(self, flow_alias, execution_alias):
		executions = self.get_authentication_flow_executions(flow_alias)
		self.logger.debug("Getting subflow with alias: {} from authentication flow: {}. Executions: {}", execution_alias, flow_alias, executions)
		for execution in executions:
			self.logger.trace("rs_get_subflow_by_alias(). Searching: '{}' in: '{}'.", execution_alias, execution)
			if "displayName" in execution:
				if execution["displayName"] == execution_alias:
					return execution
		return None


	def rs_create_realm(self, realm_json_file, temp_file):
		shutil.copyfile(realm_json_file, temp_file)
		self.local_properties.replace(temp_file)
		with open(temp_file) as json_file:
			json_data = json.load(json_file)
			self.logger.trace("json_data: {}", json_data)
			self.create_realm(json_data, skip_exists=True)


	def rs_set_default_default_client_scopes(self, client_scopes):
		self.logger.debug("Setting default default client scopes with: {}", client_scopes)
		current_scopes = self.get_default_default_client_scopes()
		self.logger.trace("Current default default client scopes: {}", current_scopes)
		for current_scope in current_scopes:
			self.logger.trace("Processing possible removal of default default client scope. id: {}, name: {}, protocol: {}", current_scope["id"], current_scope["name"], current_scope["protocol"])
			if current_scope["name"] not in client_scopes:
				self.logger.debug("Deleting default default client scope: {}", current_scope["name"])
				self.delete_default_default_client_scope(current_scope["id"])
		for new_scope in client_scopes:
			add_scope = True
			for current_scope in current_scopes:
				if current_scope["name"] == new_scope:
					add_scope = False
			if add_scope:
				new_scope_id = self.get_client_scope_id(new_scope)
				self.logger.debug("Adding default default client scope: {}, id: {}", new_scope, new_scope_id)
				self.add_default_default_client_scope(new_scope_id)


	def rs_set_default_optional_client_scopes(self, client_scopes):
		self.logger.debug("Setting default optional client scopes with: {}", client_scopes)
		current_scopes = self.get_default_optional_client_scopes()
		self.logger.trace("Current default optional client scopes: {}", current_scopes)
		for current_scope in current_scopes:
			self.logger.trace("Processing possible removal of default optional client scope. id: {}, name: {}, protocol: {}", current_scope["id"], current_scope["name"], current_scope["protocol"])
			if current_scope["name"] not in client_scopes:
				self.logger.debug("Deleting default optional client scope: {}", current_scope["name"])
				self.delete_default_optional_client_scope(current_scope["id"])
		for new_scope in client_scopes:
			add_scope = True
			for current_scope in current_scopes:
				if current_scope["name"] == new_scope:
					add_scope = False
			if add_scope:
				new_scope_id = self.get_client_scope_id(new_scope)
				self.logger.debug("Adding default optional client scope: {}, id: {}", new_scope, new_scope_id)
				self.add_default_optional_client_scope(new_scope_id)


	def rs_update_realm_attributes(self, objects_folder, realm_name, temp_file):
		self.logger.debug("Importing realm attributes")
		for directory_entry in sorted(os.scandir(objects_folder), key=lambda path: path.name):
			if directory_entry.is_file() and directory_entry.path.endswith(".json"):
				self.logger.debug("Processing file: {}", directory_entry.path)
				shutil.copyfile(directory_entry.path, temp_file)
				self.local_properties.replace(temp_file)
				with open(temp_file) as json_file:
					json_data = json.load(json_file)
					if "defaultDefaultClientScopes" in json_data:
						self.logger.debug("Setting default default client scopes")
						self.rs_set_default_default_client_scopes(json_data["defaultDefaultClientScopes"])
						json_data.pop("defaultDefaultClientScopes")
					if "defaultOptionalClientScopes" in json_data:
						self.logger.debug("Setting default optional client scopes")
						self.rs_set_default_optional_client_scopes(json_data["defaultOptionalClientScopes"])
						json_data.pop("defaultOptionalClientScopes")
					self.logger.trace("json_data: {}", json_data)
					self.update_realm(realm_name, json_data)


	def rs_import_components(self, objects_folder, realm_id, temp_file):
		self.logger.debug("Importing components from: {}", objects_folder)
		for directory_entry in sorted(os.scandir(objects_folder), key=lambda path: path.name):
			if directory_entry.is_file() and directory_entry.path.endswith(".json"):
				self.logger.debug("Processing file: {}", directory_entry.path)
				shutil.copyfile(directory_entry.path, temp_file)
				self.local_properties.replace(temp_file)
				with open(temp_file) as json_file:
					json_data = json.load(json_file)
					self.logger.trace("Component definition: {}", json_data)
					component_id = json_data["id"]
					provider_type = json_data["providerType"]
					if "parentId" in json_data:
						parent = json_data["parentId"]
					else:
						parent = realm_id
					if self.rs_component_exists(component_id, parent, provider_type):
						self.logger.debug("Component '{}' already exists. Updating...", component_id)
						self.update_component(component_id, json_data)
					else:
						self.logger.debug("Component '{}' does not exist. Creating...", component_id)
						self.create_component(json_data)
						self.logger.debug("Deleting default childs for component_id:  ", component_id)
						self.rs_delete_component_childs(component_id)


	def rs_import_idps(self, objects_folder, temp_file):
		self.logger.debug("Importing ID providers from: {}", objects_folder)
		for directory_entry in sorted(os.scandir(objects_folder), key=lambda path: path.name):
			if directory_entry.is_file() and directory_entry.path.endswith(".json"):
				self.logger.debug("Processing file: {}", directory_entry.path)
				shutil.copyfile(directory_entry.path, temp_file)
				self.local_properties.replace(temp_file)
				with open(temp_file) as json_file:
					json_data = json.load(json_file)
					self.logger.trace("ID provider definition: {}", json_data)
					idp_alias = json_data["alias"]
					if self.rs_idp_exists(idp_alias):
						self.logger.debug("ID provider '{}' already exists. Updating...", idp_alias)
						self.update_idp(idp_alias, json_data)
					else:
						self.logger.debug("Identity provider '{}' does not exist. Creating...", idp_alias)
						self.create_idp(json_data)


	def rs_update_execution(self, authentication_execution, flow_alias):
		self.logger.debug("Updating authentication flow executions")
		authentication_execution_config = ""
		if "config" in authentication_execution:
			authentication_execution_config = authentication_execution["config"]
			authentication_execution.pop("config", None)
		self.logger.debug("Updating Authentication Flow Execution using: {}", authentication_execution)
		self.update_authentication_flow_executions(authentication_execution, flow_alias)
		if authentication_execution_config != "":
			self.logger.debug("Creating execution using: {}", authentication_execution_config)
			self.create_authenticator_config(authentication_execution_config, authentication_execution["id"])
			self.logger.trace("Created execution config: {}", authentication_execution_config)


	def rs_delete_execution(self, execution_id, flow_alias):
		self.logger.debug("Deleting execution id: {}", execution_id)
		execution = self.get_authentication_flow_execution(execution_id)
		self.logger.debug("Execution to be deleted: {}", execution)
		if "flowId" not in execution:
			self.logger.debug("Execution is NOT subflow, deleting: {}", execution)
			self.delete_authentication_flow_execution(execution_id)
		else:
			self.logger.debug("Execution is subflow, getting executions. Subflow: {}", execution)
			subflow = self.get_authentication_flow_for_id(execution["flowId"])
			self.logger.debug("Subflow (full): {}", subflow)
			# delete childs first
			if "authenticationExecutions" in subflow:
				for authentication_execution in subflow["authenticationExecutions"]:
					if "flowAlias" in authentication_execution:
						self.logger.debug("Deleting subflow alias '{}'", authentication_execution["flowAlias"])
						full_subflow = self.rs_get_subflow_by_alias(flow_alias, authentication_execution["flowAlias"])
						self.logger.debug("Full subflow: '{}'", full_subflow)
						self.rs_delete_execution(full_subflow["id"], flow_alias)
			# then delete execution subflow
			self.logger.debug("Finally deleting execution id: {}", execution_id)
			self.delete_authentication_flow_execution(execution_id)


	def rs_import_authentication_flows(self, objects_folder, temp_file):
		self.logger.debug("Importing authentication flows")
		for directory_entry in sorted(os.scandir(objects_folder), key=lambda path: path.name):
			if directory_entry.is_file() and directory_entry.path.endswith(".json"):
				self.logger.debug("Processing file: {}", directory_entry.path)
				shutil.copyfile(directory_entry.path, temp_file)
				self.local_properties.replace(temp_file)
				with open(temp_file) as json_file:
					authentication_flow = json.load(json_file)
					authentication_executions = authentication_flow["authenticationExecutions"]
					self.logger.trace("json_data: {}", authentication_flow)

					# Create flow without executions (if flow does not exist)
					authentication_flow.pop("authenticationExecutions", None)
					self.logger.debug("Creating authentication flow using: {}", authentication_flow)
					flow_alias = authentication_flow["alias"]
					self.logger.trace("Flow alias: {}", flow_alias)
					# create_authentication_flow() expects payload as dict, not string
					self.create_authentication_flow(authentication_flow, skip_exists=True)

					# Delete any current (level=0) executions from flow
					current_executions = self.get_authentication_flow_executions(flow_alias)
					self.logger.trace("Current executions for flow alias '{}': {}", flow_alias, current_executions)
					for current_execution in current_executions:
						if current_execution["level"] == 0:
							self.logger.debug("Deleting execution: {}", current_execution)
							self.rs_delete_execution(current_execution["id"], flow_alias)

					# Add new executions
					for authentication_execution in authentication_executions:
						self.logger.debug("Processing execution: {}", authentication_execution)
						if "alias" in authentication_execution:
							# if subflow, delete and re-create
							execution_alias = authentication_execution["alias"]
							self.logger.debug("Searching subflow '{}' in flow '{}'", execution_alias, flow_alias)
							execution_flow = self.rs_get_subflow_by_alias(flow_alias, execution_alias)
							self.logger.debug("Subflow found: {}", execution_flow)
							if execution_flow is not None:
								self.rs_delete_execution(execution_flow["id"], flow_alias)
							# add new execution flow
							create_payload = {}
							create_payload["alias"] = execution_alias
							create_payload["type"] = "basic-flow"
							self.logger.debug("Adding subflow: {}", create_payload)
							self.create_authentication_flow_subflow(create_payload, flow_alias, skip_exists=False)
							execution_flow = self.rs_get_subflow_by_alias(flow_alias, execution_alias)
							self.logger.trace("Current subflow: {}", execution_flow)
							update_payload = {}
							update_payload["id"] = execution_flow["id"]
							for attr, value in authentication_execution.items():
								self.logger.debug("Set attr: {} with value: {} in the execution_flow", attr, value)
								update_payload[attr] = value
							self.logger.debug("Update execution in {} with: {}", flow_alias, update_payload)
							self.rs_update_execution(update_payload, flow_alias)
						else:
							create_payload = {}
							create_payload["provider"] = authentication_execution["providerId"]
							self.logger.debug("Creating subflow using: {}", create_payload)
							created_flow_execution = self.create_authentication_flow_execution(create_payload, flow_alias)
							self.logger.trace("Created subflow: {}", created_flow_execution)
							authentication_execution["id"] = created_flow_execution
							self.rs_update_execution(authentication_execution, flow_alias)


	def rs_get_execution_by_provider(self, flow_alias, execution_provider_id):
		executions = self.get_authentication_flow_executions(flow_alias)
		for execution in executions:
			self.logger.trace("execution: {}", execution)
			if execution["providerId"] == execution_provider_id:
				return execution
		return None


	def rs_set_execution_attribute(self, flow_alias, execution_provider_id, attr_name, attr_value):
		execution = self.rs_get_execution_by_provider(flow_alias, execution_provider_id)
		self.logger.debug("Current execution: {}", execution)
		execution[attr_name] = attr_value
		self.logger.debug("Updating execution to: {}", execution)
		self.update_authentication_flow_executions(execution, flow_alias)


	def rs_import_client_scopes(self, objects_folder, temp_file):
		self.logger.debug("Importing client scopes from: {}", objects_folder)
		for directory_entry in sorted(os.scandir(objects_folder), key=lambda path: path.name):
			if directory_entry.is_file() and directory_entry.path.endswith(".json"):
				self.logger.debug("Processing file: {}", directory_entry.path)
				shutil.copyfile(directory_entry.path, temp_file)
				self.local_properties.replace(temp_file)
				with open(temp_file) as json_file:
					json_data = json.load(json_file)
					self.logger.trace("Client scope definition: {}", json_data)
					client_scope_name = json_data["name"]
					client_scope_id = self.get_client_scope_id(client_scope_name)
					if client_scope_id is not None:
						self.logger.debug("Client scope '{}' already exists with internal id: '{}'. Updating attributes.", client_scope_name, client_scope_id)
						# update_client_scope() does NOT update mappers.
						self.update_client_scope(client_scope_id, json_data)
						deployed_client_scope = self.get_client_scope(client_scope_id)
						self.logger.debug("Deployed client scope: '{}'", deployed_client_scope)
						if "protocolMappers" in deployed_client_scope:
							deployed_mappers = deployed_client_scope["protocolMappers"]
							for deployed_mapper in deployed_mappers:
								deployed_mapper_id = deployed_mapper["id"]
								deployed_mapper_name = deployed_mapper["name"]
								self.logger.debug("Deleting deployed mapper '{}' ({}) from client_scope: {}", deployed_mapper_name, deployed_mapper_id, client_scope_name)
								self.delete_mapper_from_client_scope(client_scope_id, deployed_mapper_id)
						else:
							self.logger.debug("Deployed client scope '{}' ({}) has NO protocol mappers.", client_scope_name, client_scope_id)
						if "protocolMappers" in json_data:
							new_mappers = json_data["protocolMappers"]
							for new_mapper in new_mappers:
								self.logger.debug("Adding mapper: '{}' to client_scope: {}", new_mapper, client_scope_name)
								self.add_mapper_to_client_scope(client_scope_id, new_mapper)
						else:
							self.logger.debug("Updated client scope '{}' has NO protocol mappers.", client_scope_name)
						self.logger.debug("Client scope '{}' updated.", client_scope_name)
					else:
						self.logger.debug("Client scope '{}' does not exist. Creating...", client_scope_name)
						self.create_client_scope(json_data, skip_exists=True)


	def rs_import_clients(self, objects_folder, temp_file):
		self.logger.debug("Importing clients from: {}", objects_folder)
		for directory_entry in sorted(os.scandir(objects_folder), key=lambda path: path.name):
			if directory_entry.is_file() and directory_entry.path.endswith(".json"):
				self.logger.debug("Processing file: {}", directory_entry.path)
				shutil.copyfile(directory_entry.path, temp_file)
				self.local_properties.replace(temp_file)
				with open(temp_file) as json_file:
					json_data = json.load(json_file)
					self.logger.trace("Client definition: {}", json_data)
					client_id = json_data["clientId"]
					if self.rs_client_exists(client_id):
						client_keycloak_id = self.rs_get_client_keycloakid(client_id)
						self.logger.debug("Client '{}' already exists with internal id: {}. Updating...", client_id, client_keycloak_id)
						self.update_client(client_keycloak_id, json_data)
					else:
						self.logger.debug("Client '{}' does not exist. Creating...", client_id)
						self.create_client(json_data, skip_exists=True)


	def rs_import_users(self, objects_folder, temp_file):
		self.logger.debug("Importing users from: {}", objects_folder)
		for directory_entry in sorted(os.scandir(objects_folder), key=lambda path: path.name):
			if directory_entry.is_file() and directory_entry.path.endswith(".json"):
				self.logger.debug("Processing file: {}", directory_entry.path)
				shutil.copyfile(directory_entry.path, temp_file)
				self.local_properties.replace(temp_file)
				with open(temp_file) as json_file:
					json_data = json.load(json_file)
					self.logger.trace("User definition: {}", json_data)
					self.create_user(json_data, exist_ok=True)


	def rs_assign_roles_to_client(self, client, role_names):
		client_id = self.get_client_id(client)
		self.logger.debug("client_id: {}", client_id)
		user_id = self.get_client_service_account_user(client_id)["id"]
		self.logger.debug("user_id: {}", user_id)
		realm_management_client_id = self.get_client_id("realm-management")
		for role_name in role_names:
			role = self.get_client_role(realm_management_client_id, role_name)
			self.logger.debug("role: {}", role)
			self.assign_client_role(client_id=realm_management_client_id, user_id=user_id, roles=role)

