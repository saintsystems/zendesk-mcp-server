from typing import Dict, Any, List
import json
import urllib.request
import urllib.parse
import base64
import requests as _requests

from zenpy import Zenpy
from zenpy.lib.api_objects import Comment
from zenpy.lib.api_objects import Ticket as ZenpyTicket


class ZendeskClient:
    def __init__(self, subdomain: str, email: str, token: str):
        """
        Initialize the Zendesk client using zenpy lib and direct API.
        """
        self.client = Zenpy(
            subdomain=subdomain,
            email=email,
            token=token
        )

        # For direct API calls
        self.subdomain = subdomain
        self.email = email
        self.token = token
        self.base_url = f"https://{subdomain}.zendesk.com/api/v2"
        # Create basic auth header
        credentials = f"{email}/token:{token}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode('ascii')
        self.auth_header = f"Basic {encoded_credentials}"

    def get_ticket(self, ticket_id: int) -> Dict[str, Any]:
        """
        Query a ticket by its ID
        """
        try:
            ticket = self.client.tickets(id=ticket_id)
            return {
                'id': ticket.id,
                'subject': ticket.subject,
                'description': ticket.description,
                'status': ticket.status,
                'priority': ticket.priority,
                'created_at': str(ticket.created_at),
                'updated_at': str(ticket.updated_at),
                'requester_id': ticket.requester_id,
                'assignee_id': ticket.assignee_id,
                'organization_id': ticket.organization_id
            }
        except Exception as e:
            raise Exception(f"Failed to get ticket {ticket_id}: {str(e)}")

    def get_ticket_comments(self, ticket_id: int) -> List[Dict[str, Any]]:
        """
        Get all comments for a specific ticket, including attachment metadata.
        """
        try:
            comments = self.client.tickets.comments(ticket=ticket_id)
            result = []
            for comment in comments:
                attachments = []
                for a in getattr(comment, 'attachments', []) or []:
                    attachments.append({
                        'id': a.id,
                        'file_name': a.file_name,
                        'content_url': a.content_url,
                        'content_type': a.content_type,
                        'size': a.size,
                    })
                result.append({
                    'id': comment.id,
                    'author_id': comment.author_id,
                    'body': comment.body,
                    'html_body': comment.html_body,
                    'public': comment.public,
                    'created_at': str(comment.created_at),
                    'attachments': attachments,
                })
            return result
        except Exception as e:
            raise Exception(f"Failed to get comments for ticket {ticket_id}: {str(e)}")

    # Allowed image MIME types. SVG is excluded — it can contain active XML/JS content.
    _ALLOWED_IMAGE_TYPES = {'image/jpeg', 'image/png', 'image/gif', 'image/webp'}

    # Magic bytes (file signatures) for each allowed type.
    _MAGIC_BYTES: Dict[str, List[bytes]] = {
        'image/jpeg': [b'\xff\xd8\xff'],
        'image/png':  [b'\x89PNG\r\n\x1a\n'],
        'image/gif':  [b'GIF87a', b'GIF89a'],
        'image/webp': [b'RIFF'],  # RIFF....WEBP — checked further below
    }

    # 10 MB hard cap to guard against image bombs and token budget blowout.
    _MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024

    # Keep redirects bounded and only permit Zendesk-owned attachment hosts.
    _MAX_ATTACHMENT_REDIRECTS = 5

    def _validate_attachment_url(self, url: str, *, initial: bool) -> str:
        """Validate an attachment URL and return its normalized hostname.

        The authenticated initial request must go to this account's exact
        Zendesk hostname. Redirects may additionally go to Zendesk's
        zdusercontent.com CDN, but credentials are never sent there.
        """
        try:
            parsed = urllib.parse.urlsplit(url)
            hostname = (parsed.hostname or "").rstrip(".").lower()
            port = parsed.port
        except ValueError as exc:
            raise ValueError("Invalid attachment URL") from exc

        if parsed.scheme.lower() != "https":
            raise ValueError("Attachment URLs must use HTTPS")
        if not hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError("Invalid attachment URL")
        if port not in (None, 443):
            raise ValueError("Attachment URLs must use the standard HTTPS port")

        tenant_host = f"{self.subdomain.lower()}.zendesk.com"
        if initial:
            if hostname != tenant_host:
                raise ValueError(
                    f"Attachment URL must use the configured Zendesk host '{tenant_host}'"
                )
        elif not (
            hostname == tenant_host
            or hostname == "zdusercontent.com"
            or hostname.endswith(".zdusercontent.com")
        ):
            raise ValueError("Attachment redirect target is not a trusted Zendesk host")

        return hostname

    def get_ticket_attachment(self, content_url: str) -> Dict[str, Any]:
        """
        Fetch an image attachment and return base64-encoded data.

        Security measures applied:
        - Allowlist of safe image MIME types (no SVG or arbitrary binary).
        - Magic byte validation so the file header must match the declared type.
        - 10 MB size cap to prevent image bombs and excessive token usage.

        Zendesk attachment URLs redirect to zdusercontent.com (Zendesk's CDN).
        The initial URL is restricted to this account's exact Zendesk host.
        Redirects are followed manually and restricted to Zendesk's CDN.
        The Authorization header is sent only to the tenant Zendesk host and
        is never forwarded to the CDN or another redirect target.
        """
        try:
            tenant_host = self._validate_attachment_url(content_url, initial=True)
            current_url = content_url

            for redirect_count in range(self._MAX_ATTACHMENT_REDIRECTS + 1):
                current_host = self._validate_attachment_url(
                    current_url,
                    initial=(redirect_count == 0),
                )
                headers = (
                    {'Authorization': self.auth_header}
                    if current_host == tenant_host
                    else {}
                )
                response = _requests.get(
                    current_url,
                    headers=headers,
                    timeout=30,
                    stream=True,
                    allow_redirects=False,
                )

                if response.status_code not in (301, 302, 303, 307, 308):
                    break

                if redirect_count == self._MAX_ATTACHMENT_REDIRECTS:
                    raise ValueError("Attachment redirect limit exceeded")
                location = response.headers.get('Location')
                if not location:
                    raise ValueError("Attachment redirect did not include a Location header")
                next_url = urllib.parse.urljoin(current_url, location)
                self._validate_attachment_url(next_url, initial=False)
                current_url = next_url

            response.raise_for_status()

            content_type = response.headers.get('Content-Type', '').split(';')[0].strip().lower()

            if content_type not in self._ALLOWED_IMAGE_TYPES:
                raise ValueError(
                    f"Attachment type '{content_type}' is not allowed. "
                    f"Supported types: {sorted(self._ALLOWED_IMAGE_TYPES)}"
                )

            # Read with size cap — stops download as soon as limit is exceeded.
            chunks = []
            total = 0
            for chunk in response.iter_content(chunk_size=65536):
                total += len(chunk)
                if total > self._MAX_ATTACHMENT_BYTES:
                    raise ValueError(
                        f"Attachment exceeds the {self._MAX_ATTACHMENT_BYTES // (1024*1024)} MB size limit."
                    )
                chunks.append(chunk)
            content = b''.join(chunks)

            # Validate magic bytes to catch MIME type spoofing.
            magic_signatures = self._MAGIC_BYTES.get(content_type, [])
            if magic_signatures and not any(content.startswith(sig) for sig in magic_signatures):
                raise ValueError(
                    f"File header does not match declared content type '{content_type}'. "
                    "The attachment may be spoofed."
                )
            # Extra check for WebP: bytes 8–12 must be b'WEBP'.
            if content_type == 'image/webp' and content[8:12] != b'WEBP':
                raise ValueError("File header does not match declared content type 'image/webp'.")

            return {
                'data': base64.b64encode(content).decode('ascii'),
                'content_type': content_type,
            }
        except (ValueError, _requests.HTTPError):
            raise
        except Exception as e:
            raise Exception(f"Failed to fetch attachment from {content_url}: {str(e)}")

    def post_comment(self, ticket_id: int, comment: str, public: bool = True) -> str:
        """
        Post a comment to an existing ticket.
        """
        try:
            ticket = self.client.tickets(id=ticket_id)
            ticket.comment = Comment(
                html_body=comment,
                public=public
            )
            self.client.tickets.update(ticket)
            return comment
        except Exception as e:
            raise Exception(f"Failed to post comment on ticket {ticket_id}: {str(e)}")

    def get_tickets(self, page: int = 1, per_page: int = 25, sort_by: str = 'created_at', sort_order: str = 'desc') -> Dict[str, Any]:
        """
        Get the latest tickets with proper pagination support using direct API calls.

        Args:
            page: Page number (1-based)
            per_page: Number of tickets per page (max 100)
            sort_by: Field to sort by (created_at, updated_at, priority, status)
            sort_order: Sort order (asc or desc)

        Returns:
            Dict containing tickets and pagination info
        """
        try:
            # Cap at reasonable limit
            per_page = min(per_page, 100)

            # Build URL with parameters for offset pagination
            params = {
                'page': str(page),
                'per_page': str(per_page),
                'sort_by': sort_by,
                'sort_order': sort_order
            }
            query_string = urllib.parse.urlencode(params)
            url = f"{self.base_url}/tickets.json?{query_string}"

            # Create request with auth header
            req = urllib.request.Request(url)
            req.add_header('Authorization', self.auth_header)
            req.add_header('Content-Type', 'application/json')

            # Make the API request
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode())

            tickets_data = data.get('tickets', [])

            # Process tickets to return only essential fields
            ticket_list = []
            for ticket in tickets_data:
                ticket_list.append({
                    'id': ticket.get('id'),
                    'subject': ticket.get('subject'),
                    'status': ticket.get('status'),
                    'priority': ticket.get('priority'),
                    'description': ticket.get('description'),
                    'created_at': ticket.get('created_at'),
                    'updated_at': ticket.get('updated_at'),
                    'requester_id': ticket.get('requester_id'),
                    'assignee_id': ticket.get('assignee_id')
                })

            return {
                'tickets': ticket_list,
                'page': page,
                'per_page': per_page,
                'count': len(ticket_list),
                'sort_by': sort_by,
                'sort_order': sort_order,
                'has_more': data.get('next_page') is not None,
                'next_page': page + 1 if data.get('next_page') else None,
                'previous_page': page - 1 if data.get('previous_page') and page > 1 else None
            }
        except urllib.error.HTTPError as e:
            error_body = e.read().decode() if e.fp else "No response body"
            raise Exception(f"Failed to get latest tickets: HTTP {e.code} - {e.reason}. {error_body}")
        except Exception as e:
            raise Exception(f"Failed to get latest tickets: {str(e)}")

    def get_all_articles(self) -> Dict[str, Any]:
        """
        Fetch help center articles as knowledge base.
        Returns a Dict of section -> [article].
        """
        try:
            # Get all sections
            sections = self.client.help_center.sections()

            # Get articles for each section
            kb = {}
            for section in sections:
                articles = self.client.help_center.sections.articles(section.id)
                kb[section.name] = {
                    'section_id': section.id,
                    'description': section.description,
                    'articles': [{
                        'id': article.id,
                        'title': article.title,
                        'body': article.body,
                        'updated_at': str(article.updated_at),
                        'url': article.html_url
                    } for article in articles]
                }

            return kb
        except Exception as e:
            raise Exception(f"Failed to fetch knowledge base: {str(e)}")

    def create_ticket(
        self,
        subject: str,
        description: str,
        requester_id: int | None = None,
        assignee_id: int | None = None,
        priority: str | None = None,
        type: str | None = None,
        tags: List[str] | None = None,
        custom_fields: List[Dict[str, Any]] | None = None,
    ) -> Dict[str, Any]:
        """
        Create a new Zendesk ticket using Zenpy and return essential fields.

        Args:
            subject: Ticket subject
            description: Ticket description (plain text). Will also be used as initial comment.
            requester_id: Optional requester user ID
            assignee_id: Optional assignee user ID
            priority: Optional priority (low, normal, high, urgent)
            type: Optional ticket type (problem, incident, question, task)
            tags: Optional list of tags
            custom_fields: Optional list of dicts: {id: int, value: Any}
        """
        try:
            ticket = ZenpyTicket(
                subject=subject,
                description=description,
                requester_id=requester_id,
                assignee_id=assignee_id,
                priority=priority,
                type=type,
                tags=tags,
                custom_fields=custom_fields,
            )
            created_audit = self.client.tickets.create(ticket)
            # Fetch created ticket id from audit
            created_ticket_id = getattr(getattr(created_audit, 'ticket', None), 'id', None)
            if created_ticket_id is None:
                # Fallback: try to read id from audit events
                created_ticket_id = getattr(created_audit, 'id', None)

            # Fetch full ticket to return consistent data
            created = self.client.tickets(id=created_ticket_id) if created_ticket_id else None

            return {
                'id': getattr(created, 'id', created_ticket_id),
                'subject': getattr(created, 'subject', subject),
                'description': getattr(created, 'description', description),
                'status': getattr(created, 'status', 'new'),
                'priority': getattr(created, 'priority', priority),
                'type': getattr(created, 'type', type),
                'created_at': str(getattr(created, 'created_at', '')),
                'updated_at': str(getattr(created, 'updated_at', '')),
                'requester_id': getattr(created, 'requester_id', requester_id),
                'assignee_id': getattr(created, 'assignee_id', assignee_id),
                'organization_id': getattr(created, 'organization_id', None),
                'tags': list(getattr(created, 'tags', tags or []) or []),
            }
        except Exception as e:
            raise Exception(f"Failed to create ticket: {str(e)}")

    @staticmethod
    def _build_search_query(
        text: str | None = None,
        status: str | None = None,
        include_tags: str | None = None,
        exclude_tags: str | None = None,
        priority: str | None = None,
        assignee: str | None = None,
        organization: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        solved_start_date: str | None = None,
        solved_end_date: str | None = None,
        has_attachments: bool | None = None,
    ) -> str:
        """Build a Zendesk search query string from structured parameters."""
        parts = ["type:ticket"]

        if text:
            parts.append(f'"{text}"')
        if status:
            for s in status.split(","):
                parts.append(f"status:{s.strip()}")
        if include_tags:
            for tag in include_tags.split(","):
                parts.append(f"tags:{tag.strip()}")
        if exclude_tags:
            for tag in exclude_tags.split(","):
                parts.append(f"-tags:{tag.strip()}")
        if priority:
            for p in priority.split(","):
                parts.append(f"priority:{p.strip()}")
        if assignee:
            parts.append(f"assignee:{assignee}")
        if organization:
            parts.append(f"organization:{organization}")
        if start_date:
            parts.append(f"created>{start_date}")
        if end_date:
            parts.append(f"created<{end_date}")
        if solved_start_date:
            parts.append(f"solved>{solved_start_date}")
        if solved_end_date:
            parts.append(f"solved<{solved_end_date}")
        if has_attachments:
            parts.append("has_attachment:true")

        return " ".join(parts)

    def search_tickets(
        self,
        text: str | None = None,
        status: str | None = None,
        include_tags: str | None = None,
        exclude_tags: str | None = None,
        priority: str | None = None,
        assignee: str | None = None,
        organization: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        solved_start_date: str | None = None,
        solved_end_date: str | None = None,
        has_attachments: bool | None = None,
        page_size: int = 100,
        after_cursor: str | None = None,
    ) -> Dict[str, Any]:
        """Search for Zendesk tickets using the search API."""
        query = self._build_search_query(
            text=text, status=status, include_tags=include_tags,
            exclude_tags=exclude_tags, priority=priority, assignee=assignee,
            organization=organization, start_date=start_date, end_date=end_date,
            solved_start_date=solved_start_date, solved_end_date=solved_end_date,
            has_attachments=has_attachments,
        )

        page_size = min(max(page_size, 1), 100)
        params: Dict[str, str] = {
            "query": query,
            "per_page": str(page_size),
            "sort_by": "created_at",
            "sort_order": "desc",
        }
        if after_cursor:
            params["page[after]"] = after_cursor

        query_string = urllib.parse.urlencode(params)
        url = f"{self.base_url}/search.json?{query_string}"

        try:
            req = urllib.request.Request(url)
            req.add_header("Authorization", self.auth_header)
            req.add_header("Content-Type", "application/json")

            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode())

            tickets = []
            for t in data.get("results", []):
                desc = t.get("description") or ""
                tickets.append({
                    "id": t.get("id"),
                    "subject": t.get("subject"),
                    "description": desc[:200],
                    "status": t.get("status"),
                    "priority": t.get("priority"),
                    "tags": t.get("tags", []),
                    "created_at": t.get("created_at"),
                    "updated_at": t.get("updated_at"),
                    "requester_id": t.get("requester_id"),
                    "assignee_id": t.get("assignee_id"),
                    "organization_id": t.get("organization_id"),
                })

            meta = data.get("meta", {})
            links = data.get("links", {})
            has_more = meta.get("has_more", False)
            next_cursor = meta.get("after_cursor") if has_more else None
            # Fallback for offset-based pagination responses
            if not has_more and "next_page" in data:
                has_more = data["next_page"] is not None

            return {
                "tickets": tickets,
                "total_count": data.get("count", len(tickets)),
                "has_more": has_more,
                "next_cursor": next_cursor,
            }
        except urllib.error.HTTPError as e:
            error_body = e.read().decode() if e.fp else "No response body"
            if e.code == 429:
                retry_after = e.headers.get("Retry-After", "unknown")
                raise Exception(f"Rate limited by Zendesk. Retry after {retry_after} seconds.")
            raise Exception(f"Search failed: HTTP {e.code} - {e.reason}. {error_body}")
        except Exception as e:
            if "Rate limited" in str(e):
                raise
            raise Exception(f"Failed to search tickets: {str(e)}")

    def count_tickets(
        self,
        text: str | None = None,
        status: str | None = None,
        include_tags: str | None = None,
        exclude_tags: str | None = None,
        priority: str | None = None,
        assignee: str | None = None,
        organization: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        solved_start_date: str | None = None,
        solved_end_date: str | None = None,
        has_attachments: bool | None = None,
    ) -> Dict[str, int]:
        """Count Zendesk tickets matching the given filters."""
        query = self._build_search_query(
            text=text, status=status, include_tags=include_tags,
            exclude_tags=exclude_tags, priority=priority, assignee=assignee,
            organization=organization, start_date=start_date, end_date=end_date,
            solved_start_date=solved_start_date, solved_end_date=solved_end_date,
            has_attachments=has_attachments,
        )

        query_string = urllib.parse.urlencode({"query": query})
        url = f"{self.base_url}/search/count.json?{query_string}"

        try:
            req = urllib.request.Request(url)
            req.add_header("Authorization", self.auth_header)
            req.add_header("Content-Type", "application/json")

            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode())

            return {"count": data.get("count", 0)}
        except urllib.error.HTTPError as e:
            error_body = e.read().decode() if e.fp else "No response body"
            if e.code == 429:
                retry_after = e.headers.get("Retry-After", "unknown")
                raise Exception(f"Rate limited by Zendesk. Retry after {retry_after} seconds.")
            raise Exception(f"Count failed: HTTP {e.code} - {e.reason}. {error_body}")
        except Exception as e:
            if "Rate limited" in str(e):
                raise
            raise Exception(f"Failed to count tickets: {str(e)}")

    def update_ticket(self, ticket_id: int, **fields: Any) -> Dict[str, Any]:
        """
        Update a Zendesk ticket with provided fields using Zenpy.

        Supported fields include common ticket attributes like:
        subject, status, priority, type, assignee_id, requester_id,
        tags (list[str]), custom_fields (list[dict]), due_at, etc.
        """
        try:
            # Load the ticket, mutate fields directly, and update
            ticket = self.client.tickets(id=ticket_id)
            for key, value in fields.items():
                if value is None:
                    continue
                setattr(ticket, key, value)

            # This call returns a TicketAudit (not a Ticket). Don't read attrs from it.
            self.client.tickets.update(ticket)

            # Fetch the fresh ticket to return consistent data
            refreshed = self.client.tickets(id=ticket_id)

            return {
                'id': refreshed.id,
                'subject': refreshed.subject,
                'description': refreshed.description,
                'status': refreshed.status,
                'priority': refreshed.priority,
                'type': getattr(refreshed, 'type', None),
                'created_at': str(refreshed.created_at),
                'updated_at': str(refreshed.updated_at),
                'requester_id': refreshed.requester_id,
                'assignee_id': refreshed.assignee_id,
                'organization_id': refreshed.organization_id,
                'tags': list(getattr(refreshed, 'tags', []) or []),
            }
        except Exception as e:
            raise Exception(f"Failed to update ticket {ticket_id}: {str(e)}")