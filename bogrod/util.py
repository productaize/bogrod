from collections import Counter

import yaml


def dict_merge(destination, source, delete_on='__delete__', subset=None):
    """
    Merge two dictionaries, including sub dicts

    Args:
        destination (dict): the dictionary to merge into
        source (dict): the dictionary to merge from
        delete_on (obj): for each entry in source, its value is
            compared to match delete_on, if it does the key will
            be deleted in the destination dict. Defaults to '__delete__'
        subset (callable): optional, only merge item
            if subset(key, value) is True

    See Also:
        https://stackoverflow.com/a/20666342/890242
    """
    dict_merge.DELETE = delete_on
    for key, value in source.items():
        if callable(subset) and not subset(key, value):
            continue
        if isinstance(value, dict):
            # get node or create one
            node = destination.setdefault(key, {})
            dict_merge(node, value, delete_on=delete_on)
        else:
            if value == dict_merge.DELETE and key in destination:
                del destination[key]
            else:
                destination[key] = value
    return destination


def tabulate_data(data, index, columns):
    counters = {}
    for d in data:
        key = tuple(d[c] for c in columns)
        if key not in counters:
            counters[key] = Counter()
        counters[key][d[index]] += 1

    # Create table headers and rows
    headers = [index] + [f'{c}\n{val}' for c in columns for val in sorted(set(d[c] for d in data))]
    rows = []
    for val in sorted(set(d[index] for d in data)):
        row = [val]
        for c in columns:
            for col_val in sorted(set(d[c] for d in data)):
                key = (col_val,) if len(columns) == 1 else (col_val,)
                if key in counters and val in counters[key]:
                    row.append(counters[key][val])
                else:
                    row.append(0)
        rows.append(row)
    rows.append(['Total'] + [sum(row[i] for row in rows) for i in range(1, len(headers))])
    return rows, headers


def tryOr(fn, else_fn):
    # try fn(), if exception call else_fn() if callable, return its value otherwise
    try:
        return fn()
    except:
        return else_fn() if callable(else_fn) else else_fn


def wait(s, delay=1, sustain_ctrl_c=3):
    """
    drop-in for time.sleep() with status updates and Ctrl-C support

    Args:
        s (int): the number of seconds to wait
        delay (int): the time to wait between updates
        sustain_ctrl_c (int): the number of Ctrl-C presses to sustain before raising KeyboardInterrupt

    Usage:
        for delay in wait(seconds):
            print(f'waiting for {delay} seconds')
    """
    import time
    if not hasattr(wait, '_control_c_count'):
        wait._control_c_count = 0

    try:
        while s:
            yield str(s)
            time.sleep(delay)
            s -= 1
    except KeyboardInterrupt:
        wait._control_c_count += 1
        if wait._control_c_count >= sustain_ctrl_c:
            raise
        pass


# adapted from https://stackoverflow.com/a/66853182/890242
class SafeNoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True
