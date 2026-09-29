#!/bin/python3
import json
import os
import ipaddress
import configparser
import datetime
import threading
try:
    from pymisp import MISPAttribute, MISPSighting
except Exception:
    MISPAttribute = None
    MISPSighting = None

workflow_url = "https://X"
headers = {
    "Content-Type": "application/json"
}

json_data = {
    "text": "C2 Txt Warning ",
    "title": "New C2 ",
    "themeColor": "0076D7"  
}

# Runtime MISP client injected by alerts.py. Keep None until initialized.
misp = None
_SIGHTING_BATCH_LOCK = threading.Lock()


def _sighting_batch_file():
    return os.environ.get(
        'MISP_SIGHTING_BATCH_FILE',
        os.path.join(os.path.dirname(__file__), 'misp_sighting_batch.json')
    )


def _load_sighting_batch_state():
    try:
        with open(_sighting_batch_file(), 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}
    events = data.get('events')
    if not isinstance(events, dict):
        events = {}
    return {'events': events}


def _save_sighting_batch_state(data):
    fp = _sighting_batch_file()
    tmp = fp + '.tmp'
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, fp)
    except Exception:
        pass


def _ensure_batch_event(data, event_id):
    events = data.setdefault('events', {})
    eid = str(event_id)
    ev = events.setdefault(eid, {})
    pending = ev.get('pending')
    if not isinstance(pending, list):
        pending = []
    ev['pending'] = pending
    if not isinstance(ev.get('last_flush_date'), str):
        ev['last_flush_date'] = ''
    return ev


def _normalize_batch_ips(ip_values):
    out = []
    seen = set()
    for ip in ip_values or []:
        s = str(ip or '').strip()
        if not s or not is_valid_ip(s):
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def enqueue_sightings(event_id, ip_values):
    """Queue candidate sighting IPs for daily batch processing."""
    event_id = str(event_id).strip()
    if not event_id:
        return 0
    ips = _normalize_batch_ips(ip_values)
    if not ips:
        return 0
    with _SIGHTING_BATCH_LOCK:
        st = _load_sighting_batch_state()
        ev = _ensure_batch_event(st, event_id)
        pending_set = set(ev.get('pending', []))
        for ip in ips:
            if ip not in pending_set:
                ev['pending'].append(ip)
                pending_set.add(ip)
        _save_sighting_batch_state(st)
        return len(ev.get('pending', []))


def remove_queued_sightings(event_id, ip_values):
    """Remove queued sighting candidates (used when IOC attribute is deleted)."""
    event_id = str(event_id).strip()
    if not event_id:
        return 0
    targets = set(_normalize_batch_ips(ip_values))
    if not targets:
        return 0
    with _SIGHTING_BATCH_LOCK:
        st = _load_sighting_batch_state()
        ev = _ensure_batch_event(st, event_id)
        before = len(ev.get('pending', []))
        ev['pending'] = [ip for ip in ev.get('pending', []) if ip not in targets]
        removed = before - len(ev.get('pending', []))
        _save_sighting_batch_state(st)
    return max(0, removed)


def run_observation_hook(hook):
    """Local-only; caller must durably consume the flag BEFORE invoking."""
    from monitor.delivery_adapters import valid_id
    if (not isinstance(hook, dict) or set(hook) != {'kind', 'event_id', 'ip'}
            or not valid_id(hook['event_id']) or not is_valid_ip(hook['ip'])):
        return False
    function = {'enqueue_sightings': enqueue_sightings,
                'remove_queued_sightings': remove_queued_sightings}.get(hook['kind'])
    if function is None:
        return False
    try:
        function(hook['event_id'], [hook['ip']])
        return True
    except Exception:
        return False


def flush_sightings_step(adapter, progress=None, *, today=None):
    """One metered HTTP operation, using the existing best-effort queue.

    A fixed day/cursor checkpoint avoids per-IP retry maps. Failures stay queued
    for the next UTC day; a crash can lose a day's attempt, not the queue item.
    Caller must re-capture current binding authority and budget each step.
    """
    from monitor.delivery_adapters import result
    if adapter.channel != 'misp' or adapter.error:
        return result('blocked', adapter.error or 'destination_invalid')
    today = today or datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d')
    event_id = adapter._event
    progress = progress or {}
    with _SIGHTING_BATCH_LOCK:
        state = _load_sighting_batch_state()
        event = _ensure_batch_event(state, event_id)
        if event['last_flush_date'] == today:
            return result('acked')
        if event.get('flush_day') != today:
            event.update(flush_day=today, flush_cursor='')
        pending = sorted(_normalize_batch_ips(event['pending']))
        if progress:
            ip = progress.get('ip')
            if ip not in pending or progress.get('binding_id') != adapter.binding_id:
                return result('failed', 'payload_invalid')
        else:
            ip = next((ip for ip in pending if ip > event.get('flush_cursor', '')), None)
            if ip is None:
                event['last_flush_date'] = today
                _save_sighting_batch_state(state)
                return result('acked')
            # Consume before network. A crashed read remains best effort and
            # cannot turn restart into an immediate sighting retry storm.
            event['flush_cursor'] = ip
            _save_sighting_batch_state(state)
    outcome = adapter.sighting_step(ip, progress)
    if outcome['state'] == 'acked':
        remove_queued_sightings(event_id, [ip])
    return outcome


def flush_sightings_batch(event_id, force=False):
    """Flush queued sightings once per UTC day (or force immediately)."""
    if misp is None:
        print("MISP client is not initialized; cannot flush sighting batch.")
        return False
    if MISPSighting is None:
        print("PyMISP is not available; cannot flush sighting batch.")
        return False

    event_id = str(event_id).strip()
    if not event_id:
        return False

    today = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d')
    with _SIGHTING_BATCH_LOCK:
        st = _load_sighting_batch_state()
        ev = _ensure_batch_event(st, event_id)
        pending = list(ev.get('pending', []))
        last_flush = ev.get('last_flush_date', '')
        if not pending:
            return True
        if (not force) and last_flush == today:
            return False

    succeeded = []
    for ip in pending:
        try:
            ok = update_sighting_by_value(event_id, ip)
        except Exception:
            ok = False
        if ok:
            succeeded.append(ip)

    with _SIGHTING_BATCH_LOCK:
        st = _load_sighting_batch_state()
        ev = _ensure_batch_event(st, event_id)
        current = list(ev.get('pending', []))
        if succeeded:
            succ = set(succeeded)
            current = [ip for ip in current if ip not in succ]
        ev['pending'] = current
        ev['last_flush_date'] = today
        _save_sighting_batch_state(st)

    print(
        f"Sighting batch flush event={event_id} attempted={len(pending)} "
        f"succeeded={len(succeeded)} remaining={len(current)}"
    )
    return True



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
    """Legacy best-effort helper, never treat an error envelope as success."""
    from monitor.delivery_adapters import event_attributes, valid_id
    if misp is None or MISPSighting is None:
        return False
    try:
        attributes = event_attributes(misp.get_event(event_id), str(event_id))
        attribute = next((a for a in attributes if a['type'] == 'ip-src'
                          and a['value'] == attribute_value), None)
        if attribute is None:
            return False
        sighting = MISPSighting()
        sighting.value, sighting.event_id, sighting.type = attribute_value, event_id, sighting_type
        response = misp.add_sighting(sighting, attribute=str(attribute['id']))
        if not isinstance(response, dict) or 'errors' in response or 'error' in response:
            return False
        value = response.get('Sighting')
        return (isinstance(value, dict) and valid_id(value.get('id'))
                and str(value.get('event_id')) == str(event_id)
                and str(value.get('attribute_id')) == str(attribute['id'])
                and str(value.get('type')) == str(sighting_type))
    except Exception:
        return False

# Function to get all existing IP attributes as a set
def get_existing_ips(attributes):
    existing_ips = set()
    for attribute in attributes:
        if attribute['type'] == 'ip-src':
            existing_ips.add(attribute['value'])
    return existing_ips



def _legacy_entries(ip_list):
    entries = []
    for item in ip_list or []:
        if isinstance(item, (tuple, list)) and item:
            ip = str(item[0])
            label = str(item[1]) if len(item) > 1 else 'unknown'
            source = str(item[2]).upper() if len(item) > 2 else 'TXT'
        else:
            ip, label, source = str(item), 'unknown', 'TXT'
        if not is_valid_ip(ip):
            raise ValueError('payload_invalid')
        entries.append((ip, label, source))
    return entries


def add_unique_ips(event_id, ip_list):
    """True iff every requested IP is proven present; compatibility only.

    Daily observations enqueue locally; scheduler flushing is separate. This
    legacy client helper is not the bounded delivery worker transport.
    """
    from monitor.delivery_adapters import event_attributes, validated_add
    if misp is None or MISPAttribute is None:
        return False
    try:
        entries = _legacy_entries(ip_list)
        attributes = event_attributes(misp.get_event(event_id), str(event_id))
    except Exception:
        return False
    existing = get_existing_ips(attributes)
    originally_existing = set(existing)
    candidates = set()
    ok = True
    for ip, label, source in entries:
        if ip in existing:
            if ip in originally_existing:
                candidates.add(ip)
            continue
        attribute = MISPAttribute()
        attribute.type = 'ip-src'
        attribute.value = ip
        attribute.comment = f"{'NST-2-1' if source == 'A' else 'NST-2-2'} {label}"
        try:
            proven = validated_add(misp.add_attribute(event_id, attribute), str(event_id), ip)
        except Exception:
            proven = False
        if proven:
            existing.add(ip)
        else:
            ok = False
    if candidates:
        try:
            enqueue_sightings(event_id, sorted(candidates))
        except Exception:
            pass  # independent best-effort observation, not attribute ACK
    return ok


def remove_ips(event_id, ip_list):
    """Compatibility wrapper: validate every delete and re-read absence."""
    from monitor.delivery_adapters import event_attributes, validated_delete
    if misp is None:
        return False
    try:
        targets = {ip for ip, _, _ in _legacy_entries(ip_list)}
        if not targets:
            return True
        for _ in range(2001):
            attributes = event_attributes(misp.get_event(event_id), str(event_id))
            matches = [a for a in attributes if a['type'] == 'ip-src' and a['value'] in targets]
            if not matches:
                try:
                    remove_queued_sightings(event_id, sorted(targets))
                except Exception:
                    pass
                return True
            if not validated_delete(misp.delete_attribute(str(matches[0]['id']))):
                return False
    except Exception:
        return False
    return False


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
