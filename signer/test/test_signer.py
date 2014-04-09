from signer import Signer
from datetime import datetime, timedelta
from base64 import urlsafe_b64encode


def test_verify_signature():
    signer = Signer(b'secret', 'sha1')
    msg = b'some msg'
    sig = signer.get_signature(msg)
    assert len(sig)
    assert signer.verify_signature(msg, sig)


def test_sign():
    signer = Signer(b'secret')
    msg = b'some msg'
    dumped = signer.sign(msg)
    assert signer.verify(dumped) == msg


def test_object():
    signer = Signer(b'secret')
    obj = dict(key=1, value='value')
    dumped = signer.sign_json(obj)
    obj = signer.verify_json(dumped)
    assert obj['key'] == 1
    assert obj['value'] == 'value'


def test_record():
    signer = Signer(b'secret')
    l = ('1', 'value')
    dumped = signer.sign_record(l)
    k1, k2 = signer.verify_record(dumped)
    assert k1 == '1'
    assert k2 == 'value'


def test_str():
    signer = Signer(b'secret')
    msg = "message"
    signed = signer.sign_str(msg)
    assert msg == signer.verify_str(signed)


def test_expires():
    signer = Signer(b'secret')
    l = ('2', 'value')
    tomorrow = datetime.utcnow() + timedelta(days=1)
    dumped = signer.sign_record(l, expires=tomorrow)
    k1, k2 = signer.verify_record(dumped)
    assert k1 == '2'
    assert k2 == 'value'

    yesterday = datetime.utcnow() + timedelta(days=-1)
    dumped = signer.sign_record(l, expires=yesterday)
    assert None is signer.verify_record(dumped)


def test_bad_base64():
    signer = Signer(b'secret')
    raw = 'asdf'
    assert None is signer.verify_record(raw)


def test_bad_signature():
    signer = Signer(b'secret')
    raw = urlsafe_b64encode(b'data').decode()
    assert None is signer.verify_record(raw)


def test_sha1():
    signer = Signer(b'secret key', method='sha1', digest_size=20)
    tomorrow = datetime.utcnow() + timedelta(days=1)
    signed = signer.sign(b'message', expires=tomorrow)
    assert b'message' == signer.verify(signed)
