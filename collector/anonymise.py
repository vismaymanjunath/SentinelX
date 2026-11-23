"""The collector's anonymiser instance: local mapping store + identity of THIS machine. Everything outgoing passes through it
before the privacy firewall and the durable outbox (see engine.emit / heartbeat)."""
from common import anon as A
from . import config

store = A.Store(config.ANON_MAP_PATH)
_ids = A.detect_identity(config.DEVICE_NAME if config.REMOTE else "", config.SLUG if config.REMOTE else "",
                         config.LAPTOP_ID, config.EXTRA_IDENTIFIERS)
anonymiser = A.Anonymiser(store, _ids, enabled=config.ANONYMISE)
ALIAS = anonymiser.alias if config.ANONYMISE else None
# what the host sees for this device in entity ids / labels
PUBLIC_SLUG = anonymiser.slug if (config.ANONYMISE and config.REMOTE) else config.SLUG
PUBLIC_LABEL = ALIAS if (config.ANONYMISE and config.REMOTE) else config.DEVICE_NAME
# a collector enrolled under its real name (before anonymisation existed) still has an identifying collector id at the host
LEGACY_IDENTITY = bool(config.ANONYMISE and config.REMOTE and not config.COLLECTOR_ID.lower().endswith(anonymiser.slug))
