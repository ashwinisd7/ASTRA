from typing import List, Dict, Any
from astra_recon.enumerators.base import BaseEnumerator
from astra_recon.models import DiscoveredUser
from astra_recon.utils.http_client import HttpClient


class RestApiEnumerator(BaseEnumerator):
    """
    WordPress REST API Enumeration (/wp-json/wp/v2/users)
    WordPress exposes user objects containing login slugs, IDs, and display names
    via the public WP-JSON REST API unless explicitly filtered or disabled.
    """

    name = "rest_api"
    description = "Queries the WP REST API endpoints (/wp-json/wp/v2/users and ?rest_route=/wp/v2/users)"

    def run(
        self,
        target_url: str,
        client: HttpClient,
        context: Dict[str, Any],
    ) -> List[DiscoveredUser]:
        users: List[DiscoveredUser] = []
        seen_usernames = set()

        # 1. Standard REST API users endpoint
        standard_endpoint = f"{target_url}/wp-json/wp/v2/users"
        resp = client.safe_get(standard_endpoint)

        if resp.is_success:
            parsed = resp.json()
            if isinstance(parsed, list):
                for item in parsed:
                    slug = item.get("slug")
                    uid = item.get("id")
                    name = item.get("name")
                    if slug and slug not in seen_usernames:
                        seen_usernames.add(slug)
                        users.append(
                            DiscoveredUser(
                                username=slug,
                                slug=slug,
                                user_id=uid,
                                display_name=name,
                                evidence="/wp-json/wp/v2/users",
                                technique="rest_api",
                                is_admin_candidate=(
                                    slug.lower() in ("admin", "administrator", "root")
                                    or uid == 1
                                ),
                            )
                        )
                if users:
                    return users

        # 2. Alternative route when plain permalinks are configured (?rest_route=/wp/v2/users)
        route_endpoint = f"{target_url}/?rest_route=/wp/v2/users"
        resp_route = client.safe_get(route_endpoint)
        if resp_route.is_success:
            parsed = resp_route.json()
            if isinstance(parsed, list):
                for item in parsed:
                    slug = item.get("slug")
                    uid = item.get("id")
                    name = item.get("name")
                    if slug and slug not in seen_usernames:
                        seen_usernames.add(slug)
                        users.append(
                            DiscoveredUser(
                                username=slug,
                                slug=slug,
                                user_id=uid,
                                display_name=name,
                                evidence="/?rest_route=/wp/v2/users",
                                technique="rest_api",
                                is_admin_candidate=(
                                    slug.lower() in ("admin", "administrator", "root")
                                    or uid == 1
                                ),
                            )
                        )
                if users:
                    return users

        # 3. Individual user endpoint probing (/wp-json/wp/v2/users/<id>)
        # Useful when list endpoint is restricted but single object access is open
        max_id = context.get("max_authors", 5)
        for user_id in range(1, max_id + 1):
            single_endpoint = f"{target_url}/wp-json/wp/v2/users/{user_id}"
            single_resp = client.safe_get(single_endpoint)
            if single_resp.is_success:
                data = single_resp.json()
                if isinstance(data, dict) and "slug" in data:
                    slug = data.get("slug")
                    if slug and slug not in seen_usernames:
                        seen_usernames.add(slug)
                        users.append(
                            DiscoveredUser(
                                username=slug,
                                slug=slug,
                                user_id=user_id,
                                display_name=data.get("name"),
                                evidence=f"/wp-json/wp/v2/users/{user_id}",
                                technique="rest_api",
                                is_admin_candidate=(
                                    slug.lower() in ("admin", "administrator", "root")
                                    or user_id == 1
                                ),
                            )
                        )

        # 4. Embedded post authors (/wp-json/wp/v2/posts?_embed)
        if not users:
            posts_endpoint = f"{target_url}/wp-json/wp/v2/posts?_embed"
            posts_resp = client.safe_get(posts_endpoint)
            if posts_resp.is_success:
                posts_data = posts_resp.json()
                if isinstance(posts_data, list):
                    for post in posts_data:
                        embedded = post.get("_embedded", {})
                        authors = embedded.get("author", [])
                        for author in authors:
                            slug = author.get("slug")
                            uid = author.get("id")
                            if slug and slug not in seen_usernames:
                                seen_usernames.add(slug)
                                users.append(
                                    DiscoveredUser(
                                        username=slug,
                                        slug=slug,
                                        user_id=uid,
                                        display_name=author.get("name"),
                                        evidence="/wp-json/wp/v2/posts?_embed",
                                        technique="rest_api",
                                        is_admin_candidate=(
                                            slug.lower() in ("admin", "administrator", "root")
                                            or uid == 1
                                        ),
                                    )
                                )

        return users
