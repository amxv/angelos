---
title: Write and send mail
description: Prepare a message, review exactly what will be sent, and handle the result without accidental duplicates.
summary: New messages, replies, forwards, saved drafts, and send receipts.
order: 11
category: Use your inbox
---

Angelos separates preparing a message from sending it. Ask your assistant to prepare the message, review the complete result, and approve that exact version before it sends.

Preparation requires send permission, the operator's sending switch, and a configured durable Redis store. It does not submit mail. If sending is unavailable, the assistant can still help write text in your conversation.

## Prepare a new message or reply

> Prepare an email to recipient@example.com with the subject “Project update” saying the requested update is ready. Show me the complete message before sending.

For an existing exchange:

> Read this message and prepare a reply thanking the sender for the update. Show me who will receive it and the full text, including any quotation.

A reply normally uses the source message's Reply-To addresses, or From if Reply-To is absent. Reply-all also includes visible To/Cc participants, excluding configured self addresses. Original Bcc recipients are not inherited.

> Prepare a reply-all to this message. Keep the response brief, and show me every To and Cc address before sending.

Recipients derived from a message still need review. Ask for an explicit change if someone should be added or removed. Replies quote the original text by default; you can ask to omit it. Missing or invalid threading information can prevent a reply, in which case a separately reviewed new message may be appropriate.

## Choose what a forward includes

> Prepare a forward to recipient@example.com with a short introduction and the invoice attachment only. Show me the quoted text and selected files before sending.

Forwarding normally quotes readable original text. Original attachments are not included unless explicitly selected. You can instead omit the original text or request the original message as an `.eml` attachment.

An attached original can disclose much more than a quotation: it retains original headers and embedded attachments, apart from the outer Bcc and Resent-Bcc fields. Private information inside attachments remains. Review that scope deliberately before choosing this mode.

## Review the exact preparation

Check:

1. The sender and every To, Cc, and Bcc recipient.
2. The subject and complete text, including quoted material.
3. The HTML alternative, if present.
4. Included attachments, omitted source files, and warnings.
5. Whether and how a Sent copy will be saved.

The preparation is fixed for 15 minutes. Changing the wording, recipient list, or attachments requires a new preparation and review. Approval of an earlier version does not carry over. Your assistant client handles confirmation; Angelos's content check cannot establish that a person actually approved it.

Prepared content is temporarily stored in the operator's configured service. See [private-data handling](/docs/safety#stored-data).

## Save a draft for later

“Draft this” can mean writing text in chat, saving a mailbox draft, or preparing a send. Say which you want:

> Save a new draft in my mailbox for later. Do not send it.

Saving requires mailbox-write permission and enabled writes. A new draft goes to the discovered Drafts folder, or a folder you choose.

To continue an existing draft:

> Open this saved draft with Angelos’s draft reader. Show me its recipients, full text and attachments. Don’t change it yet.

For a supported draft, ask:

> Save a revised copy with the new wording. Keep the original draft. Update the HTML version too, or clear it if we only want plain text.

Revisions create a new copy in the same folder by default. They never overwrite or delete the original. If another mail client has changed the draft, Angelos asks for a fresh read instead of silently applying changes to an older version.

When you are ready:

> Prepare this saved version for sending and show me the complete preview. Don’t send until I approve it.

Preparation captures that reviewed version for 15 minutes; later edits in your mail app do not update it. Sending does not remove the saved draft. If you want to tidy old copies, review that as a separate mailbox change.

Some drafts cannot be safely rebuilt, including inline-image, signed/encrypted, and unsupported-header messages. Angelos rejects them instead of dropping content. Use your original mail app for those drafts or for an in-place edit. [Exact draft limits](/docs/tools#saved-draft-lifecycle)

## Understand the send result

**Accepted** means the outgoing mail server accepted the message. It does not verify delivery to the recipient.

Gmail and Microsoft Graph save outgoing mail in Sent automatically; Angelos must not request an extra copy. Graph acceptance means queued, not delivered. Other providers may also save a copy. If a separate Sent-copy step fails after acceptance, the message may already be on its way. Do not resend just to repair filing.

If the result is **sending**, **unknown**, or interrupted, ask:

> Check the receipt for this prepared message. Do not send it again or prepare a duplicate.

Angelos provides a read-only status check. Missing or expired status is not proof that nothing was sent. Resolve uncertainty using the available receipt and provider evidence before deciding on another message; any new send needs its own review.

For recipient selection and forwards, see [Natural replies and forwards](/docs/natural-messages). Agent authors should use the [Agent playbook](/docs/agent-guide).
