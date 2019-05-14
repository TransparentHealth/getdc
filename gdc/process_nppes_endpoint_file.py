#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: ai ts=4 sts=4 et sw=4
# Written by Alan Viars
import sys
import csv
from validate_email import validate_email
from get_direct_certificate import DCert

__author__ = "Alan Viars"


def process_endpoint_csv(input_csv_filepath,
                          output_csv_filepath="output.csv"):
    output_fieldnames = [
        "NPI",
        "EndpointType",
        "Endpoint",
        "ValidEmail",
        "ValidDirect",
        "Details"]
    input_fh = open(input_csv_filepath, 'r', newline='')
    output_fh = open(output_csv_filepath, 'w', newline='')
    input_csv = csv.reader(input_fh, delimiter=',')
    writer = csv.DictWriter(output_fh, fieldnames=output_fieldnames)
    writer.writeheader()
    """#skip the first row """
    next(input_csv)

    for row in input_csv:
        print("Processing", row[3], "for NPI", row[0])
        outrow = {}
        outrow['NPI'] = row[0]
        outrow['EndpointType'] = row[1]
        outrow['Endpoint'] = row[3]
        if outrow['EndpointType'] in ("DIRECT", "EMAIL"):
            outrow["ValidEmail"] = validate_email(outrow['Endpoint'])

        if outrow['EndpointType'] == "DIRECT":
            dc = DCert(outrow['Endpoint'])
            dc.validate_certificate(False)

            if dc.result['is_found']:
                outrow['ValidDirect'] = "1"
            else:
                outrow['ValidDirect'] = "0"

        outrow['Details'] = ""
        writer.writerow(outrow)

    print(input_csv_filepath, output_csv_filepath)
    input_fh.close()
    output_fh.close()


if __name__ == "__main__":

    # Get the file from the command line
    if len(sys.argv) not in (2, 3):
        print("You must supply an NPPES endpoint input file")
        print("Usage: getdc [nppes_endpoint_file] [nppes_output_file]")
        sys.exit(1)
    else:
        if len(sys.argv) is 2:
            process_endpoint_csv(sys.argv[1])
        else:
            process_endpoint_csv(sys.argv[1], sys.argv[2])
