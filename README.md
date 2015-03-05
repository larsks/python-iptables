This is a Python wrapper for the `iptables` command.

## Examples

Create a new chain in the `filter` table if it does not already exist:

    import iptables

    if iptables.filter.chain_exists('example'):
        chain = iptables.filter.chains['example']
    else:
        chain = iptables.filter.new_chain('example')

Add a rule to the new chain:

    chain.append(Rule('-s 192.168.1.0/24 -p tcp --dport 80 -j ACCEPT'))

Link the new chain to the 'INPUT' chain:

    iptables.filter.chains['INPUT'].append(Rule('-j example'))

Set the default policy for the `INPUT` chain to `DROP`:

    iptables.filter.chains['INPUT'].policy = 'DROP'

Get a list of all the chains in the `nat` table:

    for chain in iptables.nat.chains:
        print chain

