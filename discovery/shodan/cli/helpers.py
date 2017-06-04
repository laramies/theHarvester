'''
Helper methods to create your own CLI commands.
'''
import click
import os

from .settings import SHODAN_CONFIG_DIR

def get_api_key():
    '''Returns the API key of the current logged-in user.'''
    shodan_dir = os.path.expanduser(SHODAN_CONFIG_DIR)
    keyfile = shodan_dir + '/api_key'

    # If the file doesn't yet exist let the user know that they need to
    # initialize the shodan cli
    if not os.path.exists(keyfile):
        raise click.ClickException('Please run "shodan init <api key>" before using this command')

    # Make sure it is a read-only file
    os.chmod(keyfile, 0o600)

    with open(keyfile, 'r') as fin:
        return fin.read().strip()

    raise click.ClickException('Please run "shodan init <api key>" before using this command')
