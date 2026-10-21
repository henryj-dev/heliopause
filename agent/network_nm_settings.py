"""Bounded child for libnm's semantic comparison, including system-owned WG secrets.

stdout/stderr are fixed diagnostics only. Profile material arrives over stdin, never argv.
The parent owns the writer lock and imposes the command timeout/process lifetime.
"""
import os
import sys


def matches(identity, filename, content):
    import gi
    gi.require_version('NM', '1.0')
    from gi.repository import NM, GLib
    keyfile = GLib.KeyFile.new()
    text = content.decode('ascii')
    keyfile.load_from_data(text, len(text), GLib.KeyFileFlags.NONE)
    expected = NM.keyfile_read(keyfile, os.path.dirname(filename), NM.KeyfileHandlerFlags.NONE, None, None)
    expected.normalize()
    client = NM.Client.new(None)
    if client.get_version() != '1.56.0':
        return False
    remote = client.get_connection_by_uuid(identity)
    if remote is None or remote.get_unsaved() or remote.get_filename() != filename:
        return False
    actual = NM.SimpleConnection.new_clone(remote)
    actual.normalize()
    # Reject changed non-secret settings/secret flags before requesting any secret.
    public_actual = NM.SimpleConnection.new_clone(actual)
    public_expected = NM.SimpleConnection.new_clone(expected)
    public_actual.clear_secrets()
    public_expected.clear_secrets()
    # GI exposes this C bitmask as an enum: OR produces an invalid integer.
    # Compare secret-cleared clones with one supported flag instead.
    if not public_actual.compare(public_expected, NM.SettingCompareFlags.IGNORE_TIMESTAMP):
        return False
    actual.update_secrets('wireguard', remote.get_secrets('wireguard', None))
    actual.normalize()
    # timestamp is NM's activation bookkeeping, not approved configuration.
    return actual.compare(expected, NM.SettingCompareFlags.IGNORE_TIMESTAMP)


def main():
    try:
        if sys.argv[1:] == ['--probe']:
            import gi
            gi.require_version('NM', '1.0')
            from gi.repository import NM
            client = NM.Client.new(None)
            if (NM.MAJOR_VERSION, NM.MINOR_VERSION, NM.MICRO_VERSION) != (1, 56, 0) or client.get_version() != '1.56.0':
                return 2
            print('networkmanager-wireguard-1.56-v1')
            return 0
        content = sys.stdin.buffer.read(32769)
        if len(sys.argv) != 3 or not 1 <= len(content) <= 32768:
            return 2
        if not matches(sys.argv[1], sys.argv[2], content):
            print('mismatching')
            return 0
    except Exception:
        return 2
    print('matching')
    return 0


if __name__ == '__main__':
    sys.exit(main())
