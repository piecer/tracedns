#!/usr/bin/env python3
"""
Configuration file management utilities.
Provides simple read/write helpers and domain normalization.
"""
import json
import logging


def read_config(path):
    """
    Read a JSON config file and return as a dict.
    Returns an empty dict on missing path or read error.

    Args:
        path (str): path to the config file

    Returns:
        dict: parsed config or empty dict
    """
    if not path:
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f) or {}
    except Exception as e:
        logging.warning("read_config failed (%s): %s", path, e)
        return {}


def write_config(path, cfg):
    """
    Write cfg (a dict) to the specified path as JSON.
    Logs a warning on failure.

    Args:
        path (str): destination file path
        cfg (dict): configuration to write
    """
    if not path:
        return
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.warning("write_config failed (%s): %s", path, e)


def normalize_domains(value):
    """
    Normalize domain input into a list of dicts.

    Returns a list like:
      [{ 'name': 'example.com', 'type': 'A',
         'txt_decode': 'cafebabe_xor_base64',
         'a_decode': 'xor32_ipv4', 'a_xor_key': 'E7708E59' }, ...]
    Accepts strings, lists, or dicts. If an item is a dict and contains
    `txt_decode` / `a_decode` / `a_xor_key` fields, they are preserved.

    Args:
        value: domain information (string, list, or dict)

    Returns:
        list: normalized domain dictionaries
    """
    if not value:
        return []
    out = []
    seen = set()
    items = value if isinstance(value, list) else [value]
    for it in items:
        if it is None:
            continue
        if isinstance(it, dict):
            name = str(it.get('name', '')).strip()
            typ = str(it.get('type', 'A')).upper() if it.get('type') else 'A'
            txt_decode = it.get('txt_decode')
            a_decode = it.get('a_decode')
            a_xor_key = it.get('a_xor_key')
        else:
            s = str(it)
            # split comma/newline
            parts = [p.strip() for p in s.replace(',', '\n').splitlines() if p.strip()]
            # each part default type A
            for p in parts:
                name = p
                typ = 'A'
                txt_decode = None
                if name and name not in seen:
                    out.append({'name': name, 'type': typ})
                    seen.add(name)
            continue
        if not name or name in seen:
            continue
        d = {'name': name, 'type': typ}
        if txt_decode:
            d['txt_decode'] = txt_decode
        if a_decode is not None and str(a_decode).strip() != '':
            d['a_decode'] = str(a_decode).strip()
        if a_xor_key is not None and str(a_xor_key).strip() != '':
            d['a_xor_key'] = str(a_xor_key).strip()
        out.append(d)
        seen.add(name)
    return out
