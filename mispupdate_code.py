#!/bin/python3
import dns.resolver
import time
import requests
import json
import re
import base64
import os
import ipaddress
import socket
import struct
import copy
import configparser
import ipaddress
import binascii
from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPObject, MISPUser, MISPSighting


from typing import Union

workflow_url = "https://X"
headers = {
    "Content-Type": "application/json"
}

json_data = {
    "text": "C2 Txt Warning ",
    "title": "New C2 ",
    "themeColor": "0076D7"  
}



def load_ini_config(file_path):
    config = configparser.ConfigParser()
    config.read(file_path)
    return config

def is_valid_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Check for specific invalid IP addresses
        if ip_obj.is_loopback or ip_obj.is_unspecified:
            return False
        return True
    except ValueError:
        return False

# Function to update sighting for a specific attribute value
def update_sighting_by_value(event_id, attribute_value, sighting_type='0'):
    try:
        # Search for the attribute by value
        result = misp.search(controller='attributes', value=attribute_value, type_attribute='ip-src')
    except Exception as e:
        print(f"Error searching for attribute: {e}")
        return

    if result and 'Attribute' in result:
        for attribute in result['Attribute']:
            if attribute['value'] == attribute_value:
                sighting = MISPSighting()
                sighting.value = attribute_value
                sighting.event_id = event_id
                sighting.type = sighting_type  # '0' = false positive, '1' = seen
                try:
                    misp.add_sighting(sighting)
                    print(f"Sighting updated for attribute with value: {attribute_value}")
                except Exception as e:
                    print(f"Error adding sighting: {e}")
                return

    print(f"Attribute with value {attribute_value} not found.")

# Function to get all existing IP attributes as a set
def get_existing_ips(attributes):
    existing_ips = set()
    for attribute in attributes:
        if attribute['type'] == 'ip-src':
            existing_ips.add(attribute['value'])
    return existing_ips



# Function to add new IP attributes if they don't already exist
def add_unique_ips(event_id, ip_list):
    try:
        event = misp.get_event(event_id)
    except Exception as e:
        print(f"Error retrieving event: {e}")
        return
    
    if event:
        attributes = event['Event']['Attribute']
        existing_ips = get_existing_ips(attributes)
        added_count = 0
        
        for ip, comment in ip_list:
            if is_valid_ip(ip) == False :
                continue
            if ip not in existing_ips:
                attribute = MISPAttribute()
                attribute.type = 'ip-src'
                attribute.value = ip
                comment = 'NST-2-2 '+comment
                attribute.comment = comment
                try:
                    misp.add_attribute(event_id, attribute)
                    added_count += 1
                except Exception as e:
                    print(f"Error adding attribute {ip}: {e}")
                # Add the IP to the set after adding to avoid re-adding in the same run
                existing_ips.add(ip)
            else :  
                update_sighting_by_value(event_id,ip)
                    

        print(f"Added {added_count} new IP addresses to event {event_id}.")
    else:
        print(f"Event ID {event_id} not found.")


def merge_lists_no_duplicates(lists):
  """Merges multiple lists into a single list without duplicates.
  Args:
      lists: A list of lists to be merged.
  Returns:
      A new list containing the unique elements from all the input lists.
  """
  # Create an empty set to store the unique elements
  unique_elements = set()
  # Iterate through each list in the input lists
  for list_item in lists.values():
    # Add elements from each list to the set
    unique_elements.update(list_item)
  # Convert the set back to a list and return the result
  return list(unique_elements)

def check_list_difference(list1, list2):
  """
  Finds the difference between two lists using sets and prints the elements 
  present in only one list.

  Args:
      list1: The first list.
      list2: The second list.
  """
  ret_str=""
  difference1 = set(list1) - set(list2)  # Elements in list1 but not in list2
  difference2 = set(list2) - set(list1)  # Elements in list2 but not in list1
  
  if difference1:
    ret_str+="Remove Item : "+str(difference1)+"\n"
  if difference2:
    ret_str+="Add Item : "+str( difference2)+"\n"
  return ret_str


def read_file_to_list(filename):
  """
  Reads a file line by line and returns a list of lines.

  Args:
      filename: The path to the file.

  Returns:
      A list containing the lines from the file, without trailing newline characters.
  """
  with open(filename, 'r') as file:
    lines = file.readlines()
  return [line.rstrip() for line in lines]  # Remove trailing newline characters


def make_json_data(data,text):
    data["text"] = text

def lists_equal_ignore_order(list1, list2):
    return sorted(list1) == sorted(list2)
# Function to resolve DNS records for a domain using a specific DNS server

