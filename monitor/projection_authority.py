"""Config-owned authority for changes to the runtime security projection.

Callers hold the application config lock; this module never acquires state
ownership, starts a publisher, or constructs a configuration service.
"""


def security_projection_revision(config):
    """Read the runtime-only projection revision under config ownership."""
    revision = config.get('_security_projection_revision', 0)
    if type(revision) is not int or not 0 <= revision <= 9007199254740991:
        raise ValueError('invalid security projection revision')
    return revision


def advance_security_projection_locked(config):
    """Revoke the attached publication before changing the traversable graph.

    Invalid or exhausted revisions fail before revocation. If invalidate raises,
    propagate it without advancing this authority or authorizing a queue change;
    the publisher may already have revoked, so its epoch must never be rolled
    back or assumed valid. Successful calls count one mutation episode, including
    a final FIFO pop plus queue-key removal.
    """
    current = security_projection_revision(config)
    if current == 9007199254740991:
        raise OverflowError('security projection revision exhausted')
    revision = current + 1
    service = config.get('_config_service')
    model = getattr(service, 'read_model', None)
    if model is not None:
        model.invalidate(hard=True)
    config['_security_projection_revision'] = revision
    return revision
