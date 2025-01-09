import json
from ipaddress import IPv4Network

FORTIGATE_JSON_FILE_PATH = "forti1-1.json"
JUNOS_JSON_FILE_PATH = "junos1-1.json"

with open(FORTIGATE_JSON_FILE_PATH, "r") as file:
    forti = json.load(file)

with open(JUNOS_JSON_FILE_PATH, "r") as file:
    junos = json.load(file)

def fortigate_address_objects(address_name):
  for address in forti["configs"][0]["edits"][0]["configs"][3]["edits"]:
    if address_name == address["edit"]:
      address_subnet = IPv4Network(f'{address["subnet"][0]}/{address["subnet"][1]}').with_prefixlen
      return address_subnet                          
  else:
    return None

def fortigate_address_groups(address_name):
  address_list = []
  for address in forti["configs"][0]["edits"][0]["configs"][4]["edits"]:
    if address_name == address["edit"]:
      for member in address["member"]:
        address_list.append(fortigate_address_objects(member))
  return address_list


def fortigate_service_objects(port_name):
  ports = {}
  for port in forti["configs"][0]["edits"][0]["configs"][5]["edits"]:
    if port["edit"] == port_name:
      if "tcp-portrange" in port:
        ports["tcp"] = []
        if "-" in port["tcp-portrange"]:
          for num in range(int(port["tcp-portrange"].split("-")[0]), int(port["tcp-portrange"].split("-")[1])+1):
            ports["tcp"].append(num)
        else:
          ports["tcp"].append(int(port["tcp-portrange"]))
      if "udp-portrange" in port:
        ports["udp"] = []
        if "-" in port["udp-portrange"]:
          for num in range(int(port["udp-portrange"].split("-")[0]), int(port["udp-portrange"].split("-")[1])+1):
            ports["udp"].append(num)
        else:
          ports["udp"].append(int(port["udp-portrange"]))
  
  return ports


def fortigate_service_groups(port_group):
  for group in forti["configs"][0]["edits"][0]["configs"][6]["edits"]:
    if port_group == group["edit"]:
      return group["member"]

def fortigate_check_if_service_object(object_name):
  for port in forti["configs"][0]["edits"][0]["configs"][5]["edits"]:
    if object_name == port["edit"]:
      return True
  return False


def fortigate_get_addresses(address_name):
  address_list = []
  if address_name == "any":
    return "any"
  if type(address_name) == str:
    addresses = fortigate_address_objects(address_name)
    if addresses == None:
      return fortigate_address_groups(address_name)
    else:
      return addresses
    
  else:
    for address in address_name:
      addresses = fortigate_address_objects(address)
      if addresses == None:
        address_list.append(fortigate_address_groups(address))
      else:
        address_list.append(addresses)
    return list(set(address_list))
  
def fortigate_get_ports(port_name):
  port_dict = {
    "tcp": [],
    "udp": []
  }

  if port_name == "ALL":
    return "any"
  if type(port_name) == str:
    if fortigate_check_if_service_object(port_name):
      s_object = fortigate_service_objects(port_name)
      for protocol, ports in s_object.items():
        port_dict[protocol].extend(ports)
    else:
      s_group_list = fortigate_service_groups(port_name)
      for s_object in s_group_list:
        s_object = fortigate_service_objects(s_object)
        for protocol, ports in s_object.items():
          port_dict[protocol].extend(ports)
  else:
    for port_name_list in port_name:
      if fortigate_check_if_service_object(port_name_list):
        s_object = fortigate_service_objects(port_name_list)
        for protocol, ports in s_object.items():
          port_dict[protocol].extend(ports)
      else:
        s_group_list = fortigate_service_groups(port_name_list)
        for s_object in s_group_list:
          s_object = fortigate_service_objects(s_object)
          for protocol, ports in s_object.items():
            port_dict[protocol].extend(ports)
  
  port_dict["tcp"] = list(set(port_dict["tcp"]))
  port_dict["udp"] = list(set(port_dict["udp"]))
  return port_dict


def juniper_address_objects(address_name):
  for address in junos["configuration"]["security"]["address-book"][0]["address"]:
    if address_name == address["name"]:
      return address["ip-prefix"]
  return None

def juniper_address_groups(address_name):
  addresses = []
  for address_group in junos["configuration"]["security"]["address-book"][0]["address-set"]:
    if address_name == address_group["name"]:
      for address_object in address_group["address"]:
        addresses.append(juniper_address_objects(address_object["name"]))
  return addresses

def juniper_service_objects(port): 
  ports = {}
  for s_object in junos["configuration"]["applications"]["application"]:
    if port == s_object["name"]:
      ports[s_object["protocol"]] = []
      if "-" in s_object["destination-port"]:
        for num in range(int(s_object["destination-port"].split("-")[0]), int(s_object["destination-port"].split("-")[1])+1):
          ports[s_object["protocol"]].append(num)
      else:
          ports[s_object["protocol"]].append(int(s_object["destination-port"]))
  
  return ports



def juniper_service_groups(group_name):
  group_list = []
  for group in junos["configuration"]["applications"]["application-set"]:
    if group_name == group["name"]:
      for app in group["application"]:
        group_list.append(app["name"])
  
  return group_list


def juniper_check_if_service_object(object_name):
  for port in junos["configuration"]["applications"]["application"]:
    if port["name"] == object_name:
      return True
  return False

def juniper_get_addresses(address_name):
  address_list = []
  for address in address_name:
    if address == "any":
      return "any"
    addresses = juniper_address_objects(address)
    if addresses == None:
      address_object = juniper_address_groups(address)
      address_list.extend(address_object)
    else:
      address_list.append(addresses)

  return list(set(address_list))



def juniper_get_ports(port_name):
  port_dict = {
    "tcp": [],
    "udp": []
  }
  for port in port_name:
    if port == "any":
      return "any"
    if juniper_check_if_service_object(port):
      s_object = juniper_service_objects(port)
      for protocol, ports in s_object.items():
        port_dict[protocol].extend(ports)
    else:
      s_group_list = juniper_service_groups(port)
      for s_object in s_group_list:
        s_object = juniper_service_objects(s_object)
        for protocol, ports in s_object.items():
          port_dict[protocol].extend(ports)

  port_dict["tcp"] = list(set(port_dict["tcp"]))
  port_dict["udp"] = list(set(port_dict["udp"]))
  return port_dict



fortigate_policies = forti["configs"][0]["edits"][0]["configs"][13]["edits"]
juniper_policies = junos["configuration"]["security"]["policies"]["policy"]


forti_formated = []
for policy in fortigate_policies:
  dict = {
    policy["name"]: {
    "source_addresses": fortigate_get_addresses(policy["srcaddr"]),
    "destination_addresses": fortigate_get_addresses(policy["dstaddr"]),
    "ports" : fortigate_get_ports(policy["service"])
  }}
  forti_formated.append(dict)


junos_formated = []
for policy in juniper_policies:
    for details in policy["policy"]:
      dict = {
        details["name"]: {
        "source_addresses": juniper_get_addresses(details["match"]["source-address"]),
        "destination_addresses": juniper_get_addresses(list(set(details["match"]["desintation-address"]))),
        "ports" : juniper_get_ports(details["match"]["application"])
  }}
      junos_formated.append(dict)






print("\nChecking Fortigate policies against Juniper policies")
for f_policy in forti_formated:
  for f_name, f_details in f_policy.items():
    for j_policy in junos_formated:
      for j_name, j_details in j_policy.items():
        if f_details == j_details:
          print(f"Policy {f_name} matches policy {j_name}")
        else:
          print(f"Policy {f_name} doesn't match a policy on the juniper")

print("\nChecking Juniper policies against Fortigate policies")
for j_policy in junos_formated:
  for j_name, j_details in j_policy.items():
    for f_policy in forti_formated:
      for f_name, f_details in f_policy.items():
        if f_details == j_details:
          print(f"Policy {j_name} matches policy {f_name}")
        else:
          print(f"Policy {j_name} doesn't match a policy on the Fortigate")
