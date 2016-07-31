#!/usr/bin/env python

import time
import subprocess
import select
from pprint import pprint


def get_pipe_stats(logvalues):
    """This function will parse the logline supplied to find statistics
    recipients (who to, rejected, greylisted, accepted, count)"""
    message_id = logvalues[5]
    print "Message ID: {}".format(message_id)
    print logvalues


def strip_connecting_ip(logpart):
    """A function for stripping out connecting hostname/ips.
    For example you may see:
        smtp.domain.com[1.1.1.1]
        - or -
        [2.2.2.2]

    This function would return simply 1.1.1.1 or 2.2.2.2"""
    print logpart
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
    # print "Parsing for email address: {}".format(logpart)
    return(logpart.split('<')[1].split('>')[0])


def get_postscreen_stats(logvalues):
    """This function will parse and return the postfix incoming actions and
    stats.  Alot of mail gets weeded out here via Greylisting and DNSBL's such
    as spamhaus and barracudacentral, so lets gather stats on which blocklists
    are actively working for us"""

    client = None
    status = None
    dnsbl_rank = int()
    postscreen_action = logvalues[5]
    print logvalues
    print postscreen_action

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
        #
        #   NOQUEUE: reject: RCPT from [2.2.2.2]:51224: 550 5.7.1 Service
        #   unavailable; client [2.2.2.2] blocked using zen.spamhaus.org;
        #   from=<baddy@domain.com>, to=<localuser@localdomain.com>,
        #   proto=ESMTP, helo=<domain.com>
        #
        #   NOQUEUE: reject: RCPT from [3.3.3.3]:44750: 550 5.5.1 Protocol
        #   error; from=<baddy@baddomain.com>, to=<localuser@localdomain.com>,
        #   proto=ESMTP, helo=<smtp.baddomain.com>
        #
        smtp_subcode = logvalues[11]
        client = strip_connecting_ip(logvalues[9])
        mail_from = None
        mail_to = None
        rejected_by = None

        if '5.7.1' in smtp_subcode:
            status = "REJECT: 550"
            rejected_by = logvalues[18]
            mail_from = strip_email_address(logvalues[19])
            mail_to = strip_email_address(logvalues[20])
            print("To: {}, From: {}, Rejected by: {}").format(mail_to,
                                                              mail_from,
                                                              rejected_by)

        if '5.5.1' in smtp_subcode:
            status = "REJECT: Protocol Error"
            mail_from = strip_email_address(logvalues[14])
            mail_to = strip_email_address(logvalues[15])

    print client, status, dnsbl_rank, postscreen_action


def get_smtp_stats(logvalues):
    """Parser which attempts to understand the postfix/smtp process"""
    message_id = logvalues[5]
    print message_id
    print "Message ID: {}".format(message_id)
    print logvalues


def get_smtpd_stats(logvalues):
    """Parser to break out smtpD stats"""
    possible_status = ['timeout', 'lost', 'warning:', 'NOQUEUE:', 'connect',
                       'disconnect']
    message_id_or_status = logvalues[5]
    smtp_code = int()
    reason_code = str()
    smtp_status = str()
    mail_to = str()
    mail_from = str()
    smtp_client = str()

    if message_id_or_status in possible_status:
        print "Found DECISION: {}".format(message_id_or_status)
        if 'NOQUEUE' in message_id_or_status:
            smtp_code = logvalues[6]
            smtp_client = logvalues[9]
            reason_code = logvalues[11]
            if smtp_code == '451' and reason_code == '4.7.1':
                # Recipient address rejected: Intentional policy rejection,
                # please try again later (GREYLISTED)
                mail_to = logvalues[12]
                mail_from = logvalues[34]
                smtp_status = 'Greylisted'

            if smtp_code == '450' and reason_code == '4.1.8':
                # Sender Address Rejected, Sender's Domain not found
                smtp_client = strip_connecting_ip(logvalues[5])
                mail_from = strip_email_address(logvalues[8])
                mail_to = strip_email_address(logvalues[16])
                smtp_status = "Invalid Sender Domain"

            if smtp_code == '550' and reason_code == '5.1.0':
                # Sender Address Rejected, user unknown in virtual mailbox
                # table.  In this scenario, someone or some thing is attempting
                # to use the local SMTP server as an open relay, but sneakily.
                # They are usually using the local domain as the sending domain
                # and then some other domain, say yahoo, google, hotmail as the
                # recipient
                smtp_client = strip_connecting_ip(logvalues[9])
                mail_from = strip_email_address(logvalues[22])
                mail_to = strip_email_address(logvalues[23])
                smtp_status = "Invalid Sender"

            if smtp_code == '550' and reason_code == '5.1.1':
                # Recipient Address Rejected, user unknown in virtual mailbox
                # table.  This could be a mis-configuration of the local SMTP
                # mailbox setup - the user specified in the "To:" field doesnt
                # exist and the message is rejected.  This can also happen when
                # the sending address is Null
                smtp_client = strip_connecting_ip(logvalues[9])
                mail_from = strip_email_address(logvalues[22])
                mail_to = strip_email_address(logvalues[23])
                smtp_status = "Invalid Recipient"

            if smtp_code == '554':
                # Sender access DENIED, sent from a dynamic IP range
                smtp_client = strip_connecting_ip(logvalues[9])
                mail_from = strip_email_address(logvalues[41])
                mail_to = strip_email_address(logvalues[42])
                smtp_status = "Bad sending server"

            if 'connect' == message_id_or_status:
                smtp_client = strip_connecting_ip(logvalues[7])

            if 'disconnect' in message_id_or_status:
                smtp_client = strip_connecting_ip(logvalues[7])

        print "Rejection information:\
                SMTP Client: {} \
                MAIL FROM: {} \
                MAIL TO: {}".format(smtp_client, mail_from, mail_to)
        print " SMTP Codes: {} - {}: {}".format(smtp_code,
                                                reason_code,
                                                smtp_status)
    else:
        print "Found Message ID: {}".format(message_id_or_status)
    print logvalues


def get_qmgr_stats(logvalues):
    """TODO: fill this out"""
    message_id = logvalues[5]
    print "Message ID: {}".format(message_id)
    print logvalues


def get_local_stats(logvalues):
    """TODO: fill this out"""
    message_id = logvalues[5]
    print "Message ID: {}".format(message_id)
    print logvalues


def get_cleanup_stats(logvalues):
    """TODO: fill this out"""
    message_id = logvalues[5]
    print "Message ID: {}".format(message_id)
    print logvalues


def get_amavis_stats(logvalues):
    """TODO: fill this out"""

    '''Example amavis log line:
        amavis[17995]: (17995-04) Passed CLEAN {RelayedInbound},
        <root@localhostname> ->
        <root@localhostname>, Message-ID:
        <20160731100001.58545A1AA4@localhostname>,
        mail_id: lJwsjFx728X4, Hits: 0, size: 1270, queued_as: AA3CCA1A85, 318
        ms'''
    amavis_txn_id = logvalues[5]
    amavis_action = logvalues[6]
    amavis_msg_metadata = logvalues[7]
    amavis_size = logvalues[12]
    print logvalues, amavis_size, amavis_txn_id, amavis_action,
    amavis_msg_metadata


def parse_maillog(logline):
    """This function is the main fork-off point for determining the format in
    which the line needs to be parsed"""

    values = logline.split(None)
    postfix_process_name = values[4]

    if 'postfix/pipe' in postfix_process_name:
        # This means that the mail was delivered, most likely, so lets send it
        # over to the get_recipient_stats function to be parsed out
        print "FOUND [pipe]"
        get_pipe_stats(values)

    if 'postfix/postscreen' in postfix_process_name:
        print "FOUND [postscreen]"
        get_postscreen_stats(values)

    if 'postfix/smtp[' in postfix_process_name:
        print "FOUND [smtp]"
        get_smtp_stats(values)

    if 'postfix/smtpd' in postfix_process_name:
        print "FOUND [smtpD]"
        get_smtpd_stats(values)

    if 'postfix/qmgr' in postfix_process_name:
        print "FOUND [qmgr]"
        get_qmgr_stats(values)

    if 'postfix/local' in postfix_process_name:
        print "FOUND [local]"
        get_local_stats(values)

    if 'postfix/cleanup' in postfix_process_name:
        print "FOUND [cleanup]"
        get_cleanup_stats(values)

    if 'amavis[' in postfix_process_name:
        print "FOUND [amavis]"
        get_amavis_stats(values)


def start_tail(file_name):
    """A simple function to start tailing the log file, parsing is done in
    another function"""
    # f = subprocess.Popen(['cat', file_name],
    f = subprocess.Popen(['tail', '-F', file_name],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p = select.poll()
    p.register(f.stdout)

    while True:
        if p.poll(1):
            line = f.stdout.readline()
            if len(line) == 0:
                continue

            parse_maillog(line)

        time.sleep(1)


def main():
    start_tail('/var/log/mail.log')


if __name__ == "__main__":
    main()
