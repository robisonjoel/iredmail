#!/usr/bin/env python

import time
import subprocess
import select
from pprint import pprint


def get_recipient_stats(logvalues):
    """This function will parse the logline supplied to find statistics
    recipients (who to, rejected, greylisted, accepted, count)"""

    print logvalues


def strip_connecting_ip(logpart):
    """A function for stripping out connecting hostname/ips.
    For example you may see:
        smtp.domain.com[1.1.1.1]
        - or -
        [2.2.2.2]

    This function would return simply 1.1.1.1 or 2.2.2.2"""
    smtp_ip = logpart.split('[')[1].split(']')[0]
    return smtp_ip


def strip_email_address(logpart):
    """This function will pair a log entry's field wrappings around email
    addresses down to just the email address.

    Example:
        to=<person@recieving_place.us>
        - or -
        from=<person@sending_place.us>

    Would become:
        person@recieving_place.us
        - or -
        person@sending_place.us

    respectivly"""

    return(logpart.split['<'][1].split['>'][0])


def get_postscreen_stats(logvalues):
    """This function will parse and return the postfix incoming actions and
    stats.  Alot of mail gets weeded out here via Greylisting and DNSBL's such
    as spamhaus and barracudacentral, so lets gather stats on which blocklists
    are actively working for us"""

    client = None
    status = None
    dnsbl_rank = int()
    postscreen_action = logvalues[5]

    if 'DISCONNECT' in postscreen_action:
        # TODO: need to do something here
        client = strip_connecting_ip(logvalues[6])

    if 'CONNECT' == postscreen_action:
        status = 'CONNECTED'
        client = strip_connecting_ip(logvalues[7])

    if 'HANGUP' in postscreen_action:
        # Here it means that the incoming SMTP client didnt even handshake
        # properly and was most likely rejected
        # Example lines:
        #   HANGUP after 1.1 from [1.1.9.8]:20012 in tests after SMTP handshake
        client = strip_connecting_ip(logvalues[9])
        status = 'SMTP_HANDSHAKE_REJECT'

    if 'DNSBL' in postscreen_action:
        # Here we process the DNSBL stats and info.
        # Example lines:
        #   DNSBL rank 2 for [1.1.1.1]:55000
        #   DNSBL rank 5 for [2.2.2.2]:20012
        client = strip_connecting_ip(logvalues[9])
        dnsbl_rank = logvalues[7]
        status = "DNSBL CLASSIFICATION"

    if 'NOQUEUE' in postscreen_action:
        # Here the message was rejected, possibly SMTP codes 550, see RFC
        # 2821/821 for more information on this.  with iRedMail this is likely
        # due to greylisting
        # Example Lines:
        #   NOQUEUE: reject: RCPT from [1.1.1.]:38137: 550 5.7.1
        client = strip_connecting_ip(logvalues[9])
        status = "REJECT: 550"
        rejected_by = logvalues[19]
        mail_from = strip_connecting_ip(logvalues[19])
        mail_to = strip_email_address(logvalues[20])
        print("Mail to: {}, Mail From: {}, Rejected by: {}").format(mail_to,
                                                                    mail_from,
                                                                    rejected_by)

    print client, status, dnsbl_rank, postscreen_action


def parse_maillog(logline):
    """This function is the main fork-off point for determining the format in
    which the line needs to be parsed"""

    values = logline.split(None)
    postfix_process = values[4]

    if 'postfix/pipe' in postfix_process:
        # This means that the mail was delivered, most likely, so lets send it
        # over to the get_recipient_stats function to be parsed out
        print "FOUND [pipe]"
        get_recipient_stats(values)

    if 'postfix/postscreen' in postfix_process:
        print "FOUND [postscreen]"
        get_postscreen_stats(values)


def start_tail(file_name):
    """A simple function to start tailing the log file, parsing is done in 
    another function"""
    f = subprocess.Popen(['tail', '-F', file_name],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p = select.poll()
    p.register(f.stdout)

    while True:
        if p.poll(1):
            line = f.stdout.readline()
            parse_maillog(line)
            print line

        time.sleep(1)


def main():
    start_tail('/var/log/mail.log')


if __name__ == "__main__":
    main()
