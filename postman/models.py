from __future__ import unicode_literals
import hashlib

from django.conf import settings
try:
    from django.contrib.auth import get_user_model  # Django 1.5
except ImportError:
    from postman.future_1_5 import get_user_model
from django.core.exceptions import ValidationError
from django.core.urlresolvers import reverse
from django.db import models
try:
    from django.utils.text import Truncator  # Django 1.4
except ImportError:
    from postman.future_1_4 import Truncator
try:
    from django.utils.timezone import now  # Django 1.4 aware datetimes
except ImportError:
    from datetime import datetime
    now = datetime.now
from django.utils.translation import ugettext, ugettext_lazy as _

from . import OPTION_MESSAGES


# ordering constants
ORDER_BY_KEY = 'o'  # as 'order'
ORDER_BY_FIELDS = {
    'f': 'sender__' + get_user_model().USERNAME_FIELD,     # as 'from'
    't': 'recipient__' + get_user_model().USERNAME_FIELD,  # as 'to'
    's': 'subject',  # as 'subject'
    'd': 'sent_at',  # as 'date'
}
ORDER_BY_MAPPER = {'sender': 'f', 'recipient': 't', 'subject': 's', 'date': 'd'}  # for templatetags usage


def get_order_by(query_dict):
    """
    Return a field name, optionally prefixed for descending order, or None if not found.

    Argument:
    ``query_dict``: a dictionary to look for a key dedicated to ordering purpose

    """
    if ORDER_BY_KEY in query_dict:
        code = query_dict[ORDER_BY_KEY]  # code may be uppercase or lowercase
        order_by_field = ORDER_BY_FIELDS.get(code.lower())
        if order_by_field:
            if code.isupper():
                order_by_field = '-' + order_by_field
            return order_by_field


def get_user_representation(user):
    """
    Return a User representation for display, configurable through an optional setting.
    """
    show_user_as = getattr(settings, 'POSTMAN_SHOW_USER_AS', None)
    if isinstance(show_user_as, (unicode, str)):
        attr = getattr(user, show_user_as, None)
        if callable(attr):
            attr = attr()
        if attr:
            return unicode(attr)
    elif callable(show_user_as):
        try:
            return unicode(show_user_as(user))
        except:
            pass
    return unicode(user)  # default value, or in case of empty attribute or exception


class MessageManager(models.Manager):
    """The manager for Message."""

    def _folder(self, related, filters, option=None, order_by=None):
        """Base code, in common to the folders."""
        qs = self.get_query_set()
        if related:
            qs = qs.select_related(*related)
        if order_by:
            qs = qs.order_by(order_by)
        if isinstance(filters, (list, tuple)):
            lookups = models.Q()
            for filter in filters:
                lookups |= models.Q(**filter)
        else:
            lookups = models.Q(**filters)
        return qs.filter(lookups)

    def inbox(self, user, related=True, **kwargs):
        """
        Return accepted messages received by a user but not marked as archived or deleted.
        """
        related = ('sender',) if related else None
        filters = {
            'recipient': user,
            'recipient_archived': False,
            'recipient_deleted_at__isnull': True,
        }
        return self._folder(related, filters, **kwargs)

    def inbox_unread_count(self, user):
        """
        Return the number of unread messages for a user.

        Designed for context_processors.py and templatetags/postman_tags.py

        """
        return self.inbox(user, related=False, option=OPTION_MESSAGES).filter(read_at__isnull=True).count()

    def sent(self, user, **kwargs):
        """
        Return all messages sent by a user but not marked as archived or deleted.
        """
        related = ('recipient',)
        filters = {
            'sender': user,
            'sender_archived': False,
            'sender_deleted_at__isnull': True,
        }
        return self._folder(related, filters, **kwargs)

    def archives(self, user, **kwargs):
        """
        Return messages belonging to a user and marked as archived.
        """
        related = ('sender', 'recipient')
        filters = ({
            'recipient': user,
            'recipient_archived': True,
            'recipient_deleted_at__isnull': True,
        }, {
            'sender': user,
            'sender_archived': True,
            'sender_deleted_at__isnull': True,
        })
        return self._folder(related, filters, **kwargs)

    def trash(self, user, **kwargs):
        """
        Return messages belonging to a user and marked as deleted.
        """
        related = ('sender', 'recipient')
        filters = ({
            'recipient': user,
            'recipient_deleted_at__isnull': False,
        }, {
            'sender': user,
            'sender_deleted_at__isnull': False,
        })
        return self._folder(related, filters, **kwargs)

    def thread(self, user, filter):
        """
        Return message/conversation for display.
        """
        return self.select_related('sender', 'recipient').filter(
            filter,
            models.Q(recipient=user) | models.Q(sender=user),
        ).order_by('sent_at')

    def as_recipient(self, user, filter):
        """
        Return messages matching a filter AND being visible to a user as the recipient.
        """
        return self.filter(filter, recipient=user)

    def as_sender(self, user, filter):
        """
        Return messages matching a filter AND being visible to a user as the sender.
        """
        return self.filter(filter, sender=user)  # any status is fine

    def perms(self, user):
        """
        Return a field-lookups filter as a permission controller for a reply request.

        The user must be the recipient of the accepted, non-deleted, message

        """
        return models.Q(recipient=user) & models.Q(recipient_deleted_at__isnull=True)

    def set_read(self, user, filter):
        """
        Set messages as read.
        """
        return self.filter(
            filter,
            recipient=user,
            read_at__isnull=True,
        ).update(read_at=now())


class Message(models.Model):
    """
    A message between a User and another User or an AnonymousUser.
    """

    SUBJECT_MAX_LENGTH = 120

    subject = models.CharField(_("subject"), max_length=SUBJECT_MAX_LENGTH)
    body = models.TextField(_("body"), blank=True)
    sender = models.ForeignKey(get_user_model(), related_name='sent_messages', null=True, blank=True, verbose_name=_("sender"))
    recipient = models.ForeignKey(get_user_model(), related_name='received_messages', null=True, blank=True, verbose_name=_("recipient"))
    parent = models.ForeignKey('self', related_name='next_messages', null=True, blank=True, verbose_name=_("parent message"))
    thread = models.ForeignKey('self', related_name='child_messages', null=True, blank=True, verbose_name=_("root message"))
    sent_at = models.DateTimeField(_("sent at"), default=now)
    read_at = models.DateTimeField(_("read at"), null=True, blank=True)
    replied_at = models.DateTimeField(_("replied at"), null=True, blank=True)
    sender_archived = models.BooleanField(_("archived by sender"), default=False)
    recipient_archived = models.BooleanField(_("archived by recipient"), default=False)
    sender_deleted_at = models.DateTimeField(_("deleted by sender at"), null=True, blank=True)
    recipient_deleted_at = models.DateTimeField(_("deleted by recipient at"), null=True, blank=True)

    objects = MessageManager()

    class Meta:
        verbose_name = _("message")
        verbose_name_plural = _("messages")
        ordering = ['-sent_at', '-id']

    def __unicode__(self):
        return "{0}>{1}:{2}".format(self.obfuscated_sender, self.obfuscated_recipient, Truncator(self.subject).words(5))

    def get_absolute_url(self):
        return reverse('postman_view', args=[self.pk])

    @property
    def is_new(self):
        """Tell if the recipient has not yet read the message."""
        return self.read_at is None

    @property
    def is_replied(self):
        """Tell if the recipient has written a reply to the message."""
        return self.replied_at is not None

    def _obfuscated_email(self):
        """
        Return the email field as obfuscated, to keep it undisclosed.

        Format is:
            first 4 characters of the hash email + '..' + last 4 characters of the hash email + '@' + domain without TLD
        Example:
            foo@domain.com -> 1a2b..e8f9@domain

        """
        email = self.email
        digest = hashlib.md5(email + settings.SECRET_KEY).hexdigest()
        shrunken_digest = '..'.join((digest[:4], digest[-4:]))  # 32 characters is too long and is useless
        bits = email.split('@')
        if len(bits) != 2:
            return ''
        domain = bits[1]
        return '@'.join((shrunken_digest, domain.rsplit('.', 1)[0]))  # leave off the TLD to gain some space

    def admin_sender(self):
        """
        Return the sender either as a username or as a plain email.
        Designed for the Admin site.

        """
        if self.sender:
            return str(self.sender)
        else:
            return '<{0}>'.format(self.email)
    admin_sender.short_description = _("sender")
    admin_sender.admin_order_field = 'sender'

    # Give the sender either as a username or as a plain email.
    clear_sender = property(admin_sender)

    @property
    def obfuscated_sender(self):
        """Return the sender either as a username or as an undisclosed email."""
        if self.sender:
            return get_user_representation(self.sender)
        else:
            return self._obfuscated_email()

    def admin_recipient(self):
        """
        Return the recipient either as a username or as a plain email.
        Designed for the Admin site.

        """
        if self.recipient:
            return str(self.recipient)
        else:
            return '<{0}>'.format(self.email)
    admin_recipient.short_description = _("recipient")
    admin_recipient.admin_order_field = 'recipient'

    # Give the recipient either as a username or as a plain email.
    clear_recipient = property(admin_recipient)

    @property
    def obfuscated_recipient(self):
        """Return the recipient either as a username or as an undisclosed email."""
        if self.recipient:
            return get_user_representation(self.recipient)
        else:
            return self._obfuscated_email()

    def get_replies_count(self):
        """Return the number of accepted responses."""
        return self.next_messages.count()

    def quote(self, format_subject, format_body):
        """Return a dictionary of quote values to initiate a reply."""
        return {
            'subject': format_subject(self.subject)[:self.SUBJECT_MAX_LENGTH],
            'body': format_body(self.obfuscated_sender, self.body),
        }

    def clean(self):
        """Check some validity constraints."""
        if not (self.sender_id or self.email):
            raise ValidationError(ugettext("Undefined sender."))

    def clean_for_visitor(self):
        """Do some auto-read and auto-delete, because there is no one to do it (no account)."""
        if not self.sender_id:
            # no need to wait for a final moderation status to mark as deleted
            if not self.sender_deleted_at:
                self.sender_deleted_at = now()
        elif not self.recipient_id:
            if self.is_accepted():
                if not self.read_at:
                    self.read_at = now()
                if not self.recipient_deleted_at:
                    self.recipient_deleted_at = now()
            else:
                # rollbacks
                if self.read_at:
                    self.read_at = None
                # but stay deleted if rejected
                if self.is_pending() and self.recipient_deleted_at:
                    self.recipient_deleted_at = None

    def get_dates(self):
        """Get some dates to restore later."""
        return (self.sender_deleted_at, self.recipient_deleted_at, self.read_at)

    def set_dates(self, sender_deleted_at, recipient_deleted_at, read_at):
        """Restore some dates."""
        self.sender_deleted_at = sender_deleted_at
        self.recipient_deleted_at = recipient_deleted_at
        self.read_at = read_at
