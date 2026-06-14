# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING

from flask import g

from superset import feature_flag_manager
from superset.utils.json import loads as json_loads

if TYPE_CHECKING:
    from superset.explorables.base import Explorable
    from superset.models.core import Database
    from superset.superset_typing import QueryObjectDict

logger = logging.getLogger(__name__)


def query_requires_runtime_expansion(
    datasource: Explorable,
    query_obj: QueryObjectDict,
) -> bool:
    """
    Return whether a query needs template/SQL expansion beyond the static cache
    dimensions captured by ``QueryObject.cache_key()`` and ``get_rls_cache_key()``.

    Chart/data requests that only vary by ``filter``, time range, and dataset-level
    RLS do not need supplemental analysis. Queries with user-aware Jinja helpers
    require deeper inspection for both cache keys and template execution.
    """
    has_extra_cache_key_calls = getattr(
        datasource,
        "has_extra_cache_key_calls",
        None,
    )
    if callable(has_extra_cache_key_calls):
        return bool(has_extra_cache_key_calls(query_obj))
    return False


def add_impersonation_cache_key_if_needed(
    database: Database,
    cache_dict: dict[str, Any],
) -> None:
    """
    Add a per-user cache-key when the DB connection is configured for
    per-user caching, no-op otherwise.
    """
    extra = json_loads(database.extra or "{}")
    if (
        (
            feature_flag_manager.is_feature_enabled("CACHE_IMPERSONATION")
            and database.impersonate_user
        )
        or feature_flag_manager.is_feature_enabled("CACHE_QUERY_BY_USER")
        or extra.get("per_user_caching", False)
    ):
        if key := database.db_engine_spec.get_impersonation_key(
            getattr(g, "user", None)
        ):
            logger.debug("Adding impersonation key to cache dict: %s", key)
            cache_dict["impersonation_key"] = key
