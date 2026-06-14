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

from unittest.mock import MagicMock

from superset.utils.cache_keys import query_requires_runtime_expansion


def test_query_requires_runtime_expansion_delegates_to_datasource() -> None:
    datasource = MagicMock()
    datasource.has_extra_cache_key_calls.return_value = True

    assert query_requires_runtime_expansion(datasource, {}) is True
    datasource.has_extra_cache_key_calls.assert_called_once_with({})


def test_query_requires_runtime_expansion_without_hook() -> None:
    assert query_requires_runtime_expansion(MagicMock(), {}) is False
