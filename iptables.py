import subprocess
import six
import functools
import shlex
import logging

LOG = logging.getLogger(__name__)


class CommandError(Exception):
    def __init__(self, command, returncode, stdout, stderr):
        self.command = command
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

    def __repr__(self):
        return '<CommandError [%d]: %s>' % (
            self.returncode,
            self.stderr.splitlines()[0])

    def __str__(self):
        return repr(self)


def cmd(*args):
    '''This acts very much like subprocess.check_output, except that
    it raises CommandError if a command exits with a non-zero exit code,
    and the CommandError objects include the full command spec, a
    returncode, stdout, and stderr.'''

    LOG.debug('running command: %s', ' '.join(args))
    p = subprocess.Popen(args,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    out, err = p.communicate()

    if p.returncode != 0:
        LOG.debug('command failed [%d]: %s...',
                  p.returncode,
                  err.splitlines()[0])
        raise CommandError(args, p.returncode, out, err)

    return out


class Rule(tuple):
    '''This represents an iptables rule.  It is an immutable tuple, and can
    be created either by passing in a tuple/list/iterator or by passing in
    a string.  So either:

        rule = Rule(['-s', '192.168.1.0/24', '-j', 'ACCEPT'])

    Or:

        rule = Rule('-s 192.168.1.0/24 -j ACCEPT')

    '''

    def __new__(cls, *args):
        if isinstance(args[0], six.string_types):
            args = (shlex.split(args[0]),)

        return super(Rule, cls).__new__(cls, *args)

    def __str__(self):
        return ' '.join(self)


class Chain(object):
    '''This represents a chain in an iptables table.'''
    def __init__(self, name, table):
        self.name = name
        self.table = table
        self.iptables = table.iptables

    def __str__(self):
        return '<Chain %s:%s>' % (
            self.table.name,
            self.name)

    def __repr__(self):
        return str(self)

    def rules(self):
        '''An iterator that yields a Rule object for each rule in the
        chain.'''
        for rule in self.iptables('-S', self.name).splitlines():
            rule = Rule(rule)
            if rule[0] != '-A':
                continue

            yield Rule(rule[2:])

    def rule_exists(self, rule):
        '''Return True if the given rule exists in the chain, False
        otherwise.'''
        try:
            self.iptables('-C', self.name, *rule)
        except CommandError as err:
            if err.returncode != 1:
                raise

            return False
        else:
            return True

    @property
    def policy(self):
        '''This is property that when read returns the current default
        policy for this chain and when assigned to changes the default
        policy.'''
        for rule in self.iptables('-S', self.name).splitlines():
            rule = Rule(rule)
            if rule[0] == '-P':
                return rule[2]

        raise ValueError('chain does not have default policy')

    @policy.setter
    def policy(self, value):
        '''Set the default policy for this chain.'''
        self.iptables('-P', self.name, value)

    def append(self, rule):
        '''Append a rule to the end of the chain.'''
        self.iptables('-A', self.name, *rule)

    def insert(self, rule, pos=1):
        '''Insert a rule into the given position in the chain (by
        default position 1).'''
        self.iptables('-I', self.name, str(pos), *rule)

    def replace(self, pos, rule):
        '''Replace the rule at position `pos` with the specified rule.'''
        self.iptables('-R', self.name, str(pos), *rule)

    def zero(self):
        '''Zero the counters associated with this chain.'''
        self.iptables('-Z', self.name)

    def delete(self, rule=None, pos=None):
        '''Delete a rule from the chain, either by specifying the complete
        rule in the `rule` parameter or by specifying the position in the
        `pos` parameter.'''
        if rule is not None:
            self.iptables('-D', self.name, *rule)
        elif pos is not None:
            self.iptables('-D', self.name, str(pos))
        else:
            raise ValueError('requires either rule or position')

    def flush(self):
        '''Flush all rules in this chain.'''
        self.iptables('-F', self.name)


class ChainFinder(object):
    '''This is a shim that supports the `chains` attribute of a Table
    object.  It allows you to retrieve chains by name, as in:

        chain = iptables.filter.chains['INPUT']

    Or to iterate over the available chains in a table:

        for chain in iptables.filter.chains:
            print chain.name
    '''
    def __init__(self, table):
        self.table = table

    def __getitem__(self, k):
        return self.table.get_chain(k)

    def __iter__(self):
        for k in self.keys():
            yield self.table.get_chain(k)

    def keys(self):
        for chain in self.table.list_chains():
            yield chain


class Table(object):
    '''This represens an iptables table.'''

    def __init__(self, name='filter', netns=None):
        '''You can reference the iptables configuration in a named network
        namespace by providing the `netns` parameter.'''
        self.name = name

        prefix = ()
        if netns is not None:
            prefix = ('ip', 'netns', 'exec', netns)

        self.iptables = functools.partial(
            cmd, *(prefix + ('iptables', '-w', '-t', name)))

        self.chains = ChainFinder(self)

    def __str__(self):
        return '<Table %s>' % (self.name,)

    def __repr__(self):
        return str(self)

    def chain_exists(self, chain):
        '''Return True if the named chain exists, False otherwise.'''
        try:
            self.iptables('-S', chain)
        except CommandError:
            return False
        else:
            return True

    def list_chains(self):
        '''Return an iterator over all the chains in this table.'''
        for rule in self.iptables('-S').splitlines():
            rule = Rule(rule)
            if rule[0] in ['-P', '-N']:
                yield rule[1]

    def get_chain(self, chain):
        '''Return a reference to the named chain.'''
        if not self.chain_exists(chain):
            raise KeyError(chain)

        return Chain(chain, self)

    def create_chain(self, chain):
        '''Create a new chain in this table.'''
        self.iptables('-N', chain)
        return self.chains[chain]

    def delete_chain(self, chain):
        '''Delete a chain.'''
        self.iptables('-X', chain)

    def flush_chain(self, chain):
        '''Flush all the rules in the named chain.'''
        self.iptables('-F', chain)

    def flush_all(self):
        '''Flush rules from all the chains in this table.'''
        self.iptables('-F')

    def zero_all(self):
        '''Zero all the chain counters in this table.'''
        self.iptables('-Z')

    def rule_exists(self, chain, rule):
        '''Return True if the specified rule exists in the specified chain,
        False otherwise.'''
        chain = self.chain[chain]
        return chain.rule_exists(rule)


filter = Table('filter')
nat = Table('nat')
mangle = Table('mangle')
raw = Table('raw')
