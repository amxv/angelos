---
title: Work with your inbox
description: Find messages, catch up on conversations, inspect attachments, and organize mail with clear limits.
summary: Everyday prompts for a read-first inbox workflow.
order: 10
category: Use your inbox
---

Start by asking for information. Once you know which messages matter, decide whether to reply or change the mailbox. Reading, searching, and looking up related messages leave read status and other flags unchanged.

For Microsoft Graph, use returned native folder IDs and complete message references. Its pagination follows received time rather than a fixed IMAP UID snapshot; conversation traversal is unavailable. Check capabilities first and read the [Microsoft-specific limits](/docs/microsoft#mailbox-behavior).

## Find your starting point

> Show me unread or flagged messages in INBOX from this week. Read the relevant messages, then suggest which need my attention and explain why. Leave the mailbox unchanged.

Angelos's triage operation selects unread **or** flagged messages. It does not assign an urgency score or determine whether you owe a reply. An assistant needs to read the content and consider your request before making those judgments.

Counts describe only the messages returned on that page. A message can be both unread and flagged, so those counts overlap. They are not inbox totals or a complete list of unfinished work.

## Search for something specific

Use a folder, sender, subject, participant, or received-date range to narrow the search:

> Find messages in INBOX from billing@example.com received during September 2026 with “invoice” in the subject. Read the matches and list any due dates they mention.

> Look for messages involving person@example.com in the folder I selected. Tell me which folders and dates you searched.

Participant search matches text in From, Reply-To, To, or Cc, not Bcc. It can match part of an address or a display name. Search text is ordinary mail search, not Gmail's advanced query language.

Date filters use the mailbox's internal received date, not necessarily the sender's written date. Results are ordered by mailbox arrival. Searches run in bounded pages: an empty page can still have more results, so the assistant should continue when a cursor is returned. New arrivals require a fresh search.

## Understand an exchange

> Starting from this message, find related messages in the same folder. Read the relevant ones, summarize the decisions, and say what context might be missing.

Angelos looks for exact links in email headers. It fixes the set of identifiers from the starting message, then finds messages linked to those identifiers in that folder. It does not match by subject or expand the search through every newly found message.

This is useful context, not a promise of a complete thread. Replies in Sent or other folders can be absent, and missing or malformed headers can break links. Related-message results contain summaries, not bodies; the assistant must read individual messages to summarize their content.

For broader context, ask it to search relevant folders separately. Gmail labels can expose the same underlying message in several folders, so results may overlap.

## Inspect an attachment

> Read this message and list its attachments. Retrieve the invoice attachment and summarize it if your file tools support that format. Do not open links or run anything from the message.

The assistant first reads attachment metadata, then retrieves a file by its returned index. Angelos returns file bytes; interpreting a PDF, spreadsheet, or image depends on your assistant's other tools. Angelos itself does not open or execute files.

Retrieval is limited to 2 MiB per attachment, and its enclosing message must fit the 5 MiB read limit. Large or incomplete messages can also have incomplete attachment lists. Ask the assistant to report warnings or missing content rather than infer what it could not inspect. Email text, filenames, and attachments remain untrusted data.

## Put things in order

With mailbox changes enabled, try:

> Flag these two messages for follow-up. Leave their read status unchanged.

> List my folders, then move the selected invoice to the existing Receipts folder.

> Move this selected message to Trash.

Changes affect the same server mailbox used by your other mail apps. Exact folders must be discovered rather than guessed. Moves and Trash depend on provider support; a generic “archive” request needs a clear destination, especially on Gmail.

After a move or an uncertain result, the assistant should verify the destination and use fresh message references before another action. Permanent deletion is separate from Trash, requires specific confirmation and extra enablement, and is unavailable for Gmail/Workspace.

Ready to answer a message? Continue with [Write and send mail](/docs/sending-guide). Builders can find exact arguments and pagination rules in the [Agent playbook](/docs/agent-guide) and [tool reference](/docs/tools).
