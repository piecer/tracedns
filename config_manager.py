#!/usr/bin/env python3
"""
설정 파일 관리 모듈
"""
import json
import logging


def read_config(path):
    """
    config JSON 파일을 읽어 dict 반환합니다.
    파일 경로가 비어있거나 읽기 실패 시 빈 dict 반환합니다.
    
    Args:
        path (str): 설정 파일 경로
    
    Returns:
        dict: 설정 파일 내용 또는 빈 딕셔너리
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
    cfg(dict)를 지정된 경로에 JSON으로 저장합니다.
    실패 시 경고 로깅합니다.
    
    Args:
        path (str): 저장할 파일 경로
        cfg (dict): 저장할 설정 내용
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
    도메인 값을 정규화된 형식으로 변환합니다.
    반환: list of dicts: [{ 'name': 'example.com', 'type': 'A', 'txt_decode': 'cafebabe_xor_base64' }, ...]
    입력 허용:
      - dict에 txt_decode 필드가 있으면 그대로 반영
    
    Args:
        value: 도메인 정보 (문자열, 리스트, 또는 딕셔너리)
    
    Returns:
        list: 정규화된 도메인 정보 리스트
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
        out.append(d)
        seen.add(name)
    return out
