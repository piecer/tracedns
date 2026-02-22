#!/usr/bin/env python3
"""
히스토리 관리 모듈
"""
import os
import json
import sys
import logging

logger = logging.getLogger(__name__)



def ensure_history_dir(path):
    """
    히스토리 디렉토리를 생성합니다 (없으면).
    
    Args:
        path (str): 생성할 디렉토리 경로
    """
    try:
        os.makedirs(path, exist_ok=True)
    except Exception as e:
        logger.warning("cannot create history dir %s: %s", path, e)


def load_history_files(history_dir):
    """
    히스토리 디렉토리에서 모든 히스토리 파일을 로드합니다.
    
    기존: 도메인별 .json 파일에서 리스트를 읽어왔음.
    변경: 파일 내용이 dict이면 { meta, events, current } 형태를 기대하고 그대로 사용.
          파일 내용이 list(레거시)면 meta를 events에서 계산하여 새로운 dict 형태로 변환하여 반환.
    
    Args:
        history_dir (str): 히스토리 파일이 있는 디렉토리
    
    Returns:
        dict: { domain: { 'meta': {first_seen, last_changed}, 'events': [...], 'current': {...} } }
    """
    h = {}
    if not os.path.isdir(history_dir):
        return h
    for fn in os.listdir(history_dir):
        if not fn.endswith('.json'):
            continue
        dom = fn[:-5]
        try:
            with open(os.path.join(history_dir, fn), 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    # expected keys: 'events' (list), optional 'meta', optional 'current'
                    events = data.get('events', []) if isinstance(data.get('events', []), list) else []
                    meta = data.get('meta', {}) if isinstance(data.get('meta', {}), dict) else {}
                    current = data.get('current', {}) if isinstance(data.get('current', {}), dict) else {}
                elif isinstance(data, list):
                    # legacy: list of events -> compute meta
                    events = data
                    ts_list = [e.get('ts', 0) for e in events if isinstance(e, dict) and 'ts' in e]
                    first_seen = min(ts_list) if ts_list else 0
                    last_changed = max(ts_list) if ts_list else 0
                    meta = {'first_seen': first_seen, 'last_changed': last_changed}
                    current = {}
                else:
                    # unknown format -> skip
                    continue
                h[dom] = {'meta': meta, 'events': events, 'current': current}
        except Exception:
            # skip bad files
            pass
    return h


def persist_history_entry(history_dir, domain, history_obj):
    """
    도메인의 히스토리를 파일에 저장합니다.
    history_obj는 dict 형태 ({'meta':..., 'events':..., 'current':...})를 기대.
    레거시 리스트가 넘어오면 호환 처리합니다.
    
    Args:
        history_dir (str): 히스토리 파일을 저장할 디렉토리
        domain (str): 도메인명
        history_obj (dict or list): 저장할 히스토리 객체
    """
    try:
        ensure_history_dir(history_dir)
        fn = os.path.join(history_dir, f"{domain}.json")
        # normalize to dict
        if isinstance(history_obj, list):
            ts_list = [e.get('ts', 0) for e in history_obj if isinstance(e, dict) and 'ts' in e]
            meta = {'first_seen': min(ts_list) if ts_list else 0, 'last_changed': max(ts_list) if ts_list else 0}
            to_write = {'meta': meta, 'events': history_obj, 'current': {}}
        elif isinstance(history_obj, dict):
            meta = history_obj.get('meta', {})
            events = history_obj.get('events', []) if isinstance(history_obj.get('events', []), list) else []
            current = history_obj.get('current', {}) if isinstance(history_obj.get('current', {}), dict) else {}
            to_write = {'meta': meta, 'events': events, 'current': current}
        else:
            to_write = {'meta': {}, 'events': [], 'current': {}}
        with open(fn, 'w', encoding='utf-8') as f:
            json.dump(to_write, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.warning("cannot persist history for %s: %s", domain, e)
