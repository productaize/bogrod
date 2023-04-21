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
