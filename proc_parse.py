#!/bin/env python
"""Quick and dirty utilty to parse /proc/$PID/smaps"""

import os
import argparse
import re

# set up argument handling
PARSER = argparse.ArgumentParser(
    description='Utility to aid in determining memory usage from \
    /proc/$PID/smaps.')

PARSER.add_argument('--verbose',
                    dest='verbose',
                    action='store_true',
                    default=False,
                    help='Display values for regions / libraries.')

PARSER.add_argument('--match',
                    dest='match',
                    default=None,
                    required=False,
                    help='Library list will include only library names that \
                    match this text.  Applied before filter (if applicable).')

PARSER.add_argument('--filter',
                    dest='filter',
                    default=None,
                    required=False,
                    help='Library list will filter all library names that \
                    match this text.  Applifed after match (if applicable).')

PARSER.add_argument('--units', dest='units', default='kB',
                    required=False, help='Output using this unit (kB, or MB)')
PARSER.add_argument('smap', help='local file copy of smaps or PID')

ARGS = PARSER.parse_args()


def find_size(string, data):
    """Pulls the size that follows a LABEL:"""
    re_string = r"(%s\:)(?:\s+)([0-9]+)(?:\s)(kB)" % (string)
    size_match = re.search(re_string, data)
    if size_match:
        return int(size_match.group(2))
    return None

# simple function to check for substring
# used for filter()


def string_in_name(string, name):
    """Used to find location of field name in string.  Used for filter()"""
    if string and name and name.find(string) != -1:
        return True
    return False

# function that will convert to output unit and string-ify it


def convert_from_kb_and_stringify(value, units):
    """Converts and prints a value in kB or MB."""
    if units == 'MB':
        return '%.2f' % (value / 1024.0) + ' MB'
    else:
        return str(value) + ' kB'


def main():
    """main entry point."""
    smaps_path = ARGS.smap
    regions = []

    #
    # check to see passed argument is a file
    try:
        smaps = open(smaps_path).read()
    except IOError:
        print ' ** Failed to open file: %s' % (smaps_path)
        smaps = None

    #
    # else, try to get the details from the process's smaps
    if not smaps:
        try:
            smaps_path = os.path.join('/proc', ARGS.smap, 'smaps')
            smaps = open(smaps_path).read()
        except IOError:
            print ' ** Unable to open file, or process %s.' % (ARGS.smap)
            return 0

    # split the file's data based on XXXXXXXX-XXXXXXXX ranges
    split_list = re.split(
        r"([a-fA-F0-9]{4,16})(?:\-)([a-fA-F0-9]{4,16})(?:\s)", smaps)
    split_list.pop(0)
    # left of first split will be empty

    size_attribute_names = ['Size',
                            'Rss',
                            'Pss',
                            'Shared_Clean',
                            'Shared_Dirty',
                            'Private_Clean',
                            'Private_Dirty',
                            'Referenced',
                            'Shared_Dirty',
                            'Swap',
                            'KernelPageSize',
                            'MMUPageSize']

    # build list
    while (split_list):
        temp_region = {}
        temp_region['start'] = split_list.pop(0)
        temp_region['end'] = split_list.pop(0)
        raw_range_data = split_list.pop(0)

        # handle name
        name = re.search(r"(/.+|\[.+\])", raw_range_data)
        if name:
            temp_region['name'] = name.group(1)
        else:
            temp_region['name'] = None

        # handle permissions
        permissions = re.search(r"([rwsxp\-]{4})", raw_range_data)
        try:
            temp_region['permissions'] = permissions.group(1)
        except BaseException:
            print temp_region
            print 'failed permssions'
            print '{' + raw_range_data + '}'

        # handle major:minor device #s, and inode #
        device_and_inode = re.search(
            r"([a-fA-F0-9]{2})(?:\:)([a-fA-F0-9]{2})(?:\s)([0-9]+)",
            raw_range_data)

        temp_region['device'] = (device_and_inode.group(1),
                                 device_and_inode.group(2))
        temp_region['inode'] = int(device_and_inode.group(3))

        # parse all the size attributes
        for attribute_name in size_attribute_names:
            temp_region[attribute_name] = find_size(
                attribute_name, raw_range_data)
        regions.append(temp_region)

    # sum up all the sizes of anonymous regions
    anonymous_regions = filter(lambda x: x['name'] is None, regions)
    anonymous_region_sizes = [x['Size'] for x in anonymous_regions]
    anonymous_region_sizes_sum = sum(anonymous_region_sizes)
    anonymous_region_rss_sizes = [x['Rss'] for x in anonymous_regions]
    anonymous_region_rss_sum = sum(anonymous_region_rss_sizes)

    # add stack & heap to anonymouse regions
    anonymous_region_sizes_sum += filter(
        lambda x: x['name'] == '[heap]', regions)[0]['Size']
    anonymous_region_sizes_sum += filter(
        lambda x: x['name'] == '[stack]', regions)[0]['Size']
    anonymous_region_rss_sum += filter(
        lambda x: x['name'] == '[heap]', regions)[0]['Rss']
    anonymous_region_rss_sum += filter(
        lambda x: x['name'] == '[stack]', regions)[0]['Rss']

    # sum all specified libraries
    libraries = filter(lambda x: x['name'] is not None, regions)

    # only include libraries that contain the specified match text (if present)
    if ARGS.match:
        libraries = filter(
            lambda x: string_in_name(ARGS.match, x['name']), libraries)

    # reject libraries that contain the specified filter text (if present)
    if ARGS.filter:
        libraries = filter(
            lambda x: not string_in_name(ARGS.filter, x['name']), libraries)

    library_sizes = [x['Size'] for x in libraries]
    library_sizes_sum = sum(library_sizes)
    library_rss_sizes = [x['Rss'] for x in libraries]
    library_rss_sizes_sum = sum(library_rss_sizes)

    # sum up executable stuff
    executable_name = regions[0]['name']
    executable_regions = filter(
        lambda x: x['name'] == executable_name, regions)
    executable_region_sizes = [x['Size'] for x in executable_regions]
    executable_region_sizes_sum = sum(executable_region_sizes)
    executable_region_rss_sizes = [x['Rss'] for x in executable_regions]
    executable_region_rss_sizes_sum = sum(executable_region_rss_sizes)

    # OUTPUT stage ##
    print '\n [Anonymous Region, +Stack, +Heap Size] : ' + \
        convert_from_kb_and_stringify(anonymous_region_sizes_sum, ARGS.units)
    print ' [Anonymous Region, +Stack, +Heap Rss] : ' + \
        convert_from_kb_and_stringify(anonymous_region_rss_sum, ARGS.units)

    # print list of anonymous regions #
    if ARGS.verbose:
        for region in regions:
            print '\t' + region['start'] \
                + ':' \
                + region['end'] \
                + ' Size: ' \
                + convert_from_kb_and_stringify(region['Size'], ARGS.units) \
                + ' Rss: ' \
                + convert_from_kb_and_stringify(region['Rss'], ARGS.units)

    print ' [Stack Size: ' \
        + convert_from_kb_and_stringify(
            filter(lambda x: x['name'] == '[stack]', regions)[0]['Size'],
            ARGS.units) \
        + ' Rss: ' + convert_from_kb_and_stringify(
            filter(lambda x: x['name'] == '[stack]', regions)[0]['Rss'],
            args.units)

    print ' [Heap Size: ' \
        + convert_from_kb_and_stringify(
            filter(lambda x: x['name'] == '[heap]', regions)[0]['Size'],
            ARGS.units) \
        + ' Rss: ' + convert_from_kb_and_stringify(
            filter(lambda x: x['name'] == '[heap]', regions)[0]['Rss'],
            args.units)

    print ' [Library Size] : ' + \
        convert_from_kb_and_stringify(library_sizes_sum, ARGS.units)
    print ' [Library Rss] : ' + \
        convert_from_kb_and_stringify(library_rss_sizes_sum, ARGS.units)

    # print list of libraries #
    if ARGS.verbose:
        for library in libraries:
            print '\t' + library['name'] + ' : ' + \
                convert_from_kb_and_stringify(library['Size'], ARGS.units)
            print '\t' + library['name'] + ' : ' + \
                convert_from_kb_and_stringify(library['Rss'], ARGS.units)

    # print executable sizes #
    print ' [Executable Size] : ' + \
        convert_from_kb_and_stringify(executable_region_sizes_sum, ARGS.units)
    print ' [Executable Rss Size] : ' + \
        convert_from_kb_and_stringify(
            executable_region_rss_sizes_sum, ARGS.units)
    print ''

if __name__ == "__main__":
    main()
